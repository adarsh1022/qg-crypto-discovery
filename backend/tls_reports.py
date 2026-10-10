"""Read-only report queries over stored TLS probe evidence: a per-run summary, a page of observations, and the run's issues.

Framework-independent. Every function takes a connection that is ALREADY inside `db.read_snapshot(...)` (it refuses
otherwise), so everything in one response comes from one consistent snapshot. All numbers are computed from stored rows;
nothing is copied from the agent except the validated scan facts that are labelled as such (`scan`).

WHAT THE ROWS ARE. Each observation is ONE ACTIVE PROBE ATTEMPT by the agent against a listener on this machine, not a
passively observed connection. Direction is always "unknown", `event_count` is 1 (one probe attempt) and `packet_count` is 0
(packet counts are unavailable: nothing is captured). Only a COMPLETED handshake is a TLS finding; failed, incomplete, alert
and unknown probes are counted as probe attempts and as `not_completed`, never as findings.

Definitions (summary.totals) and how they relate to the run's own counters, in any snapshot WITHOUT a frontier:
  probe_attempts          stored observations                 == runs.record_count
  handshakes_completed    observations with outcome completed == runs.finding_count
  not_completed           probe_attempts - handshakes_completed (failed, incomplete, alert, unknown)
  endpoints               distinct (dst_ip, dst_port)
  certificates_presented  distinct catalog fingerprints linked to the run's observations (any chain position)
  leaf_certificates       distinct fingerprints at chain position 0
  issues.rejected         distinct refused sequence numbers   == runs.rejected_count
  issues.errors.total     agent scan errors (enumerate + probe) == runs.error_count

Frontier: the highest tls_observations.id visible in a snapshot (ids are assigned in insertion order, rows are never deleted).
Passing it back adds `id <= frontier` to EVERY observation query (page, total and the observation-derived summary blocks).
Issues are read live.

Certificate validity ("now") is recomputed at the request time with the agent's own rules and the default "expiring" window
(a TLS run has no expiring_days setting), per unique LEAF certificate. Nothing about trust or host names is evaluated.
"""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from . import run_state as rs, runs
from .db import QueryBudget
from .fs_record import DEFAULT_EXPIRING_DAYS, assess_at
from .reports import (DEFAULT_LIMIT, InvalidQuery, MAX_LIMIT, MAX_OFFSET, Page, _choice, _fingerprint, _int, _like, _order, _paging,
                      _required_int, _search, _term, prepare_snapshot)
from .summaries import CHECK_EVERY, DEFAULT_TOP, MAX_TOP, _check_int, _check_now, _counts, _ranked, _timestamp
from .tls_record import ATTRIBUTIONS, ERROR_KINDS, OUTCOMES, VERSIONS

TLS_SORTS = {
    "seq": "o.seq", "observed_at": "o.observed_at", "dst_ip": "o.dst_ip", "dst_port": "o.dst_port",
    "handshake_outcome": "o.handshake_outcome", "tls_version": "o.tls_version", "cipher_suite": "o.cipher_suite",
    "process_name": "o.process_name COLLATE NOCASE",
}
ORDER_CIPHERS = "handshakes DESC, cipher_suite"
FRONTIER_SCOPE = {
    "frozen": ["totals", "outcomes", "tls_versions", "cipher_suites", "process_attribution", "certificate_validity"],
    "live": ["issues", "scan"],
}
SCAN_COUNT_KEYS = ("listeners_found", "port_filtered", "policy_skipped", "targets_planned", "targets_probed")


def require_tls_run(conn: sqlite3.Connection, run_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT run_id, run_number, type, status, started_at, finished_at, agent_summary_json "
                       "FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise runs.RunNotFound(run_id)
    if row["type"] != "tls":
        raise runs.WrongRunType("not a tls run")
    return row


def current_frontier(conn: sqlite3.Connection, run_id: str) -> int:
    """The highest insertion id of the run's TLS observations in this snapshot (0 if it has none)."""
    return conn.execute("SELECT COALESCE(MAX(id), 0) FROM tls_observations WHERE run_id = ?", (run_id,)).fetchone()[0]


# ------------------------------------------------------------------ the observations query
@dataclass(frozen=True)
class TlsObservationQuery:
    outcome: str | None = None
    tls_version: str | None = None
    process_attribution: str | None = None
    dst_port: int | None = None
    fingerprint: str | None = None
    q: str | None = None
    sort: str = "seq"
    direction: str = "asc"
    limit: int = DEFAULT_LIMIT
    offset: int = 0
    frontier: int | None = None

    def __post_init__(self):
        _choice("outcome", self.outcome, OUTCOMES)
        _choice("tls_version", self.tls_version, VERSIONS)
        _choice("process_attribution", self.process_attribution, ATTRIBUTIONS)
        _int("dst_port", self.dst_port, 1, 65535)
        _search(self.q)
        object.__setattr__(self, "fingerprint", _fingerprint(self.fingerprint))
        _paging(self.limit, self.offset, self.frontier, self.sort, self.direction, TLS_SORTS)


_OBS_FROM = ("FROM tls_observations AS o "
             "LEFT JOIN tls_peer_certificates AS p0 ON p0.tls_observation_id = o.id AND p0.position = 0 "
             "LEFT JOIN certificates AS c0 ON c0.sha256 = p0.sha256")
_OBS_SELECT = ("SELECT o.id AS internal_id, o.seq, o.observed_at, o.direction, o.transport, o.src_ip, o.src_port, o.dst_ip, o.dst_port, "
               "o.handshake_outcome, o.sni, o.tls_version, o.cipher_suite, o.cert_visibility, o.pid, o.process_name, o.exe_path, "
               "o.process_attribution, o.event_count, o.packet_count, o.event_counts_json, o.evidence_confidence, o.warnings_json ")


def _where(query: TlsObservationQuery, params: dict) -> str:
    clauses = ["o.run_id = :run", "o.id <= :frontier"]
    for name, column in (("outcome", "o.handshake_outcome"), ("tls_version", "o.tls_version"),
                         ("process_attribution", "o.process_attribution"), ("dst_port", "o.dst_port")):
        value = getattr(query, name)
        if value is not None:
            clauses.append(f"{column} = :{name}")
            params[name] = value
    if query.fingerprint is not None:
        clauses.append("EXISTS (SELECT 1 FROM tls_peer_certificates AS fp WHERE fp.tls_observation_id = o.id "
                       "AND substr(fp.sha256, 1, :fp_length) = :fingerprint)")
        params["fp_length"], params["fingerprint"] = len(query.fingerprint), query.fingerprint
    if query.q is not None:
        params["q"] = _term(query.q)
        clauses.append("(" + " OR ".join([_like("o.dst_ip"), _like("o.process_name"), _like("o.exe_path"), _like("c0.subject")]) + ")")
    return " AND ".join(clauses)


def _peers_for(conn: sqlite3.Connection, ids: list[int]) -> dict[int, list[dict]]:
    """The peer certificates of a whole page of observations in ONE query, leaf first."""
    if not ids:
        return {}
    marks = ", ".join("?" * len(ids))
    out: dict[int, list[dict]] = {i: [] for i in ids}
    for row in conn.execute(
            "SELECT p.tls_observation_id AS observation, p.position, c.sha256, c.subject, c.issuer, c.not_before, c.not_after, "
            "c.key_algorithm, c.key_size, c.key_curve, c.signature_algorithm, c.is_ca "
            f"FROM tls_peer_certificates AS p JOIN certificates AS c ON c.sha256 = p.sha256 WHERE p.tls_observation_id IN ({marks}) "
            "ORDER BY p.tls_observation_id, p.position", ids):
        item = dict(row)
        owner = item.pop("observation")
        item["is_ca"] = None if item["is_ca"] is None else bool(item["is_ca"])
        out[owner].append(item)
    return out


def search_observations(conn: sqlite3.Connection, run_id: str, query: TlsObservationQuery | None = None) -> Page:
    """One page of the run's probe observations plus the total that matches the same filters under the same frontier."""
    query = query or TlsObservationQuery()
    prepare_snapshot(conn)
    require_tls_run(conn, run_id)
    frontier = query.frontier if query.frontier is not None else current_frontier(conn, run_id)
    params: dict[str, Any] = {"run": run_id, "frontier": frontier}
    where = _where(query, params)                                          # ONE builder: page and total cannot drift
    total = conn.execute(f"SELECT COUNT(*) {_OBS_FROM} WHERE {where}", params).fetchone()[0]
    rows = conn.execute(f"{_OBS_SELECT}{_OBS_FROM} WHERE {where} ORDER BY {_order(TLS_SORTS, query.sort, query.direction, 'o.seq')} "
                        "LIMIT :limit OFFSET :offset", {**params, "limit": query.limit, "offset": query.offset}).fetchall()
    peers = _peers_for(conn, [r["internal_id"] for r in rows])
    items = []
    for row in rows:
        item = dict(row)
        item["peer_certificates"] = peers[item.pop("internal_id")]
        item["warnings"] = json.loads(item.pop("warnings_json"))
        item["event_counts"] = json.loads(item.pop("event_counts_json"))
        items.append(item)
    return Page(items, total, query.limit, query.offset, frontier)


# ------------------------------------------------------------------ issues
def list_tls_issues(conn: sqlite3.Connection, run_id: str, *, limit: int = DEFAULT_LIMIT, offset: int = 0) -> dict:
    """One page of a TLS run's issues (agent scan errors, rejected records, sequence conflicts), in insertion order.

    Fixed codes only: backend codes are a closed vocabulary and agent codes were validated against `[a-z0-9_]{1,64}` at
    ingestion. TLS issues carry no path.
    """
    limit = _required_int("limit", limit, 1, MAX_LIMIT)
    offset = _required_int("offset", offset, 0, MAX_OFFSET)
    prepare_snapshot(conn)
    require_tls_run(conn, run_id)
    total = conn.execute("SELECT COUNT(*) FROM run_issues WHERE run_id = ?", (run_id,)).fetchone()[0]
    items = [dict(r) for r in conn.execute(
        "SELECT source, kind, code, path, seq FROM run_issues WHERE run_id = ? ORDER BY id LIMIT ? OFFSET ?", (run_id, limit, offset))]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


# ------------------------------------------------------------------ the per-run summary
def _scan_facts(raw: str | None) -> dict | None:
    """The agent's validated scan facts (stored at finalization), or None while the run has not finished. Claims, not evidence."""
    if raw is None:
        return None
    try:
        stored = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(stored, dict):
        return None
    out: dict[str, Any] = {"stop_reason": stored.get("stop_reason") if isinstance(stored.get("stop_reason"), str) else None,
                           "enumeration": stored.get("enumeration") if stored.get("enumeration") in ("ok", "failed") else None,
                           "targets_truncated": stored.get("targets_truncated") if isinstance(stored.get("targets_truncated"), bool) else None}
    for key in SCAN_COUNT_KEYS:
        value = stored.get(key)
        out[key] = value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
    return out


def tls_summary(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime, frontier: int | None = None,
                top_n: int = DEFAULT_TOP, budget: QueryBudget | None = None) -> dict:
    """Every report metric of one TLS run, from one snapshot (see the module docstring for the definitions)."""
    now = _check_now(now)
    top_n = _check_int("top_n", top_n, 1, MAX_TOP)
    if frontier is not None:
        frontier = _check_int("frontier", frontier, 0, 2**62)
    prepare_snapshot(conn)
    run = require_tls_run(conn, run_id)
    if frontier is None:
        frontier = current_frontier(conn, run_id)
    p = {"run": run_id, "frontier": frontier}
    scope = "o.run_id = :run AND o.id <= :frontier"

    row = conn.execute(f"SELECT COUNT(*) AS attempts, COALESCE(SUM(o.handshake_outcome = 'completed'), 0) AS completed "
                       f"FROM tls_observations AS o WHERE {scope}", p).fetchone()
    endpoints = conn.execute(f"SELECT COUNT(*) FROM (SELECT DISTINCT o.dst_ip, o.dst_port FROM tls_observations AS o WHERE {scope})", p).fetchone()[0]
    outcomes = _counts(conn.execute(f"SELECT o.handshake_outcome, COUNT(*) FROM tls_observations AS o WHERE {scope} "
                                    f"GROUP BY o.handshake_outcome", p), OUTCOMES)
    versions = _counts(conn.execute(f"SELECT o.tls_version, COUNT(*) FROM tls_observations AS o WHERE {scope} "
                                    f"AND o.handshake_outcome = 'completed' GROUP BY o.tls_version", p), VERSIONS)
    attribution = _counts(conn.execute(f"SELECT o.process_attribution, COUNT(*) FROM tls_observations AS o WHERE {scope} "
                                       f"GROUP BY o.process_attribution", p), ATTRIBUTIONS)
    ciphers = _ranked(conn, f"SELECT o.cipher_suite AS cipher_suite, COUNT(*) AS handshakes FROM tls_observations AS o WHERE {scope} "
                            f"AND o.handshake_outcome = 'completed' GROUP BY o.cipher_suite", p, ORDER_CIPHERS, top_n, ("handshakes",))
    linked = conn.execute(f"SELECT COUNT(DISTINCT l.sha256), COUNT(DISTINCT CASE WHEN l.position = 0 THEN l.sha256 END) "
                          f"FROM tls_peer_certificates AS l JOIN tls_observations AS o ON o.id = l.tls_observation_id WHERE {scope}", p).fetchone()

    if budget is not None:
        budget.check()
    validity = {"valid": 0, "expiring": 0, "expired": 0, "not_yet_valid": 0}
    leaves = conn.execute(f"SELECT c.not_before, c.not_after FROM certificates AS c WHERE c.sha256 IN ("
                          f"SELECT DISTINCT l.sha256 FROM tls_peer_certificates AS l JOIN tls_observations AS o ON o.id = l.tls_observation_id "
                          f"WHERE {scope} AND l.position = 0)", p)
    for number, cert in enumerate(leaves):
        if budget is not None and number % CHECK_EVERY == 0:
            budget.check()
        status, _days, not_yet_valid = assess_at(cert["not_before"], cert["not_after"], now, DEFAULT_EXPIRING_DAYS)
        validity[status] += 1
        validity["not_yet_valid"] += int(not_yet_valid)

    kinds = ", ".join("?" * len(ERROR_KINDS))
    by_kind = _counts(conn.execute(f"SELECT kind, COUNT(*) FROM run_issues WHERE run_id = ? AND source = 'agent' AND kind IN ({kinds}) "
                                   f"GROUP BY kind", (run_id, *ERROR_KINDS)), ERROR_KINDS)
    rejected = conn.execute("SELECT COUNT(DISTINCT seq) FROM run_issues WHERE run_id = ? AND source = 'backend' AND kind = 'rejected_record'",
                            (run_id,)).fetchone()[0]
    conflicts = conn.execute("SELECT COUNT(DISTINCT seq) FROM run_issues WHERE run_id = ? AND source = 'backend' AND kind = 'seq_conflict'",
                             (run_id,)).fetchone()[0]

    return {
        "run": {"run_id": run["run_id"], "run_number": run["run_number"], "type": run["type"], "status": run["status"],
                "final": run["status"] in rs.TERMINAL, "started_at": run["started_at"], "finished_at": run["finished_at"]},
        "as_of": _timestamp(now), "frontier": frontier, "frontier_scope": FRONTIER_SCOPE,
        "totals": {"probe_attempts": row["attempts"], "handshakes_completed": row["completed"],
                   "not_completed": row["attempts"] - row["completed"], "endpoints": endpoints,
                   "certificates_presented": linked[0], "leaf_certificates": linked[1]},
        "outcomes": outcomes, "tls_versions": versions, "cipher_suites": ciphers, "process_attribution": attribution,
        "certificate_validity": {"expiring_days": {"value": DEFAULT_EXPIRING_DAYS, "source": "default"}, "now": validity},
        "issues": {"errors": {"total": sum(by_kind.values()), "enumerate": by_kind["enumerate"], "probe": by_kind["probe"]},
                   "rejected": rejected, "seq_conflicts": conflicts},
        "scan": _scan_facts(run["agent_summary_json"]),
    }
