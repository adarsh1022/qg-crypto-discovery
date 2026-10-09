"""Aggregate reports over stored filesystem evidence: a per-run summary, run statistics and the dashboard payload.

Framework-independent and read-only. Every function takes a connection that is ALREADY inside `db.read_snapshot(...)`
(it refuses otherwise), so every number in one response comes from one consistent snapshot. All counts are computed
from stored rows; nothing is copied from the agent. No cache tables: the numbers are derived on demand.

What is compared with what (never force equality across different definitions)
  summary.totals.records           == runs.record_count     (all stored observation rows)
  summary.totals.sightings         == runs.finding_count    (rows with a certificate)
  summary.issues.rejected          == runs.rejected_count   (distinct refused sequence numbers)
  issues.errors.total              == runs.error_count      (file_errors + directory_errors + unresolved_read_errors)
  These hold in any consistent snapshot WITHOUT a frontier. `parse_failures` (malformed, unsupported, too_large plus the
  two read-error statuses) and `unique_certificates` have no run counter and are never compared with one.

Frontier
  The same insertion-id frontier as in `reports`: it freezes the SET of observations, so every observation-derived block
  (totals, breakdowns, validity, buckets, algorithms, issuers, locations, issues.errors.file_errors) is stable across
  requests. It does not freeze the run's issues: directory errors, unresolved read errors, rejected records and sequence
  conflicts are read live (they are listed in `frontier_scope.live`).

Duplicates (see reports.py): within_file = sum over (fingerprint, path) of (n - 1); across_files = sum over fingerprints
of (paths - 1); together they equal sightings - unique_certificates.

Validity
  at_discovery  stored with each sighting (the evidence at scan time), counted per sighting; `not_yet_valid` is a separate
                flag count, not a status.
  now           recomputed at the request's `now` with the run's own `expiring_days` (the agent's exact rules), counted
                per unique certificate and per sighting. `expiring_days` comes from the run's config; without one the
                agent's default applies (source: "default").

Expiry buckets (days to expiry, floor): expired (<0), 0-30, 31-90, 91-365, over-365. `expired` is exactly the status.

Ranked lists ("top" + "other")
  algorithms / signature_algorithms / issuers: groups ordered by unique certificates, then sightings, then name; the first
  `top_n` are listed and the rest are summed in `other`. Their `unique` counts are disjoint, so they add up to
  unique_certificates. Locations are not disjoint (a certificate may be seen in many places): per-location `unique` is
  that location's own distinct count, and `other` carries sightings (and observations) only. A directory is the path up
  to its last backslash, exactly as stored (no case folding).
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sqlite3
from typing import Any

from . import run_state as rs
from .fs_ingest import FILE_ERROR_STATUSES, unresolved_read_errors
from .fs_record import DIRECTORY_LEVEL_ERROR_KINDS, FORMATS, PARSE_STATUSES, assess_at, expiring_days_with_source
from .reports import MAX_FRONTIER, InvalidQuery, current_frontier, prepare_snapshot, require_filesystem_run

DEFAULT_TOP = 20
MAX_TOP = 100
MAX_SERIES = 200
DEFAULT_RECENT = 10
EXPIRY_BUCKETS = ("expired", "0-30", "31-90", "91-365", "over-365")
FAILURE_STATUSES = ("malformed", "unsupported", "too_large", "access_denied", "read_error")
RUN_TYPES = ("filesystem", "tls")
_SINCE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{3})?Z")

# Ranked-list orderings. Each ends with the group's own name(s): SQL guarantees no order among rows that tie on the earlier
# keys, so the response order must never depend on how the engine happens to group.
ORDER_ALGORITHMS = "uniq DESC, sightings DESC, key_algorithm, key_size, key_curve"
ORDER_SIGNATURES = "uniq DESC, sightings DESC, signature_algorithm"
ORDER_ISSUERS = "uniq DESC, sightings DESC, issuer"
ORDER_SCAN_ROOTS = "observations DESC, scan_root"
ORDER_DIRECTORIES = "sightings DESC, uniq DESC, directory"

FRONTIER_SCOPE = {
    "frozen": ["totals", "parse_status", "formats", "validity", "expiry_buckets", "algorithms", "signature_algorithms",
               "issuers", "locations", "issues.errors.file_errors"],
    "live": ["issues.errors.directory_errors", "issues.errors.unresolved_read_errors", "issues.rejected", "issues.seq_conflicts"],
}
_BUCKET_SQL = ("CASE WHEN {d} < 0 THEN 'expired' WHEN {d} <= 30 THEN '0-30' WHEN {d} <= 90 THEN '31-90' "
               "WHEN {d} <= 365 THEN '91-365' ELSE 'over-365' END")


def expiry_bucket(days: int) -> str:
    """The fixed bucket of a days-to-expiry value (same boundaries as the SQL used for stored values)."""
    if days < 0:
        return "expired"
    return "0-30" if days <= 30 else "31-90" if days <= 90 else "91-365" if days <= 365 else "over-365"


# ------------------------------------------------------------------ small helpers
def _check_now(now: Any) -> dt.datetime:
    if not isinstance(now, dt.datetime):
        raise InvalidQuery("now", "wrong_type")
    if now.tzinfo is None:
        raise InvalidQuery("now", "needs_a_timezone")
    return now.astimezone(dt.timezone.utc)


def _check_int(name: str, value: Any, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidQuery(name, "wrong_type")
    if not low <= value <= high:
        raise InvalidQuery(name, "out_of_range")
    return value


def _timestamp(moment: dt.datetime) -> str:
    return rs.format_ts(moment)


def _counts(rows, keys) -> dict:
    """{key: count} with every key present (zero-filled), so the shape never depends on the data."""
    out = dict.fromkeys(keys, 0)
    for key, count in rows:
        if key in out:
            out[key] = count
    return out


def _ranked(conn: sqlite3.Connection, group_sql: str, params: dict, order: str, top_n: int, additive: tuple[str, ...]) -> dict:
    """The first `top_n` groups of `group_sql` (a SELECT named g) and a summed 'other' for the rest.

    `order` and `additive` are internal constants (never caller text). `other` carries only the measures that are
    meaningful to add up across groups (`additive`, named by their SQL aliases).
    """
    sums = ", ".join(f"COALESCE(SUM({m}), 0)" for m in additive)
    total = conn.execute(f"WITH g AS ({group_sql}) SELECT COUNT(*), {sums} FROM g", params).fetchone()
    rows = conn.execute(f"WITH g AS ({group_sql}) SELECT * FROM g ORDER BY {order} LIMIT :top_n", {**params, "top_n": top_n}).fetchall()
    top = [dict(r) for r in rows]
    for item in top:
        if "uniq" in item:
            item["unique"] = item.pop("uniq")
    groups = total[0]
    other = None
    if groups > len(top):
        left = {("unique" if m == "uniq" else m): total[1 + i] - sum(item["unique" if m == "uniq" else m] for item in top)
                for i, m in enumerate(additive)}
        other = {"groups": groups - len(top), **left}
    return {"top": top, "other": other, "total_groups": groups, "limit": top_n}


# ------------------------------------------------------------------ the per-run summary
def fs_summary(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime, frontier: int | None = None,
               top_n: int = DEFAULT_TOP) -> dict:
    """Every report metric of one filesystem run, from one snapshot (see the module docstring for definitions)."""
    now = _check_now(now)
    top_n = _check_int("top_n", top_n, 1, MAX_TOP)
    if frontier is not None:
        frontier = _check_int("frontier", frontier, 0, MAX_FRONTIER)
    prepare_snapshot(conn)
    require_filesystem_run(conn, run_id)
    run = conn.execute("SELECT run_id, run_number, type, status, started_at, finished_at, config_json FROM runs WHERE run_id = ?",
                       (run_id,)).fetchone()
    if frontier is None:
        frontier = current_frontier(conn, run_id)
    threshold, threshold_source = expiring_days_with_source(json.loads(run["config_json"]))
    p = {"run": run_id, "frontier": frontier}
    scope = "o.run_id = :run AND o.id <= :frontier"

    row = conn.execute(f"SELECT COUNT(*) AS records, COALESCE(SUM(o.sha256 IS NOT NULL), 0) AS sightings, "
                       f"COUNT(DISTINCT o.sha256) AS uniq FROM fs_observations AS o WHERE {scope}", p).fetchone()
    by_status = _counts(conn.execute(f"SELECT o.parse_status, COUNT(*) FROM fs_observations AS o WHERE {scope} GROUP BY o.parse_status", p), PARSE_STATUSES)
    by_format = _counts(conn.execute(f"SELECT o.format, COUNT(*) FROM fs_observations AS o WHERE {scope} GROUP BY o.format", p), FORMATS)
    within = conn.execute(
        f"SELECT COALESCE(SUM(n - 1), 0) FROM (SELECT COUNT(*) AS n FROM fs_observations AS o WHERE {scope} AND o.sha256 IS NOT NULL "
        f"GROUP BY o.sha256, o.path)", p).fetchone()[0]
    across = conn.execute(
        f"SELECT COALESCE(SUM(paths - 1), 0) FROM (SELECT COUNT(DISTINCT o.path) AS paths FROM fs_observations AS o WHERE {scope} "
        f"AND o.sha256 IS NOT NULL GROUP BY o.sha256)", p).fetchone()[0]

    discovery = _counts(conn.execute(f"SELECT o.validity_status, COUNT(*) FROM fs_observations AS o WHERE {scope} "
                                     f"AND o.validity_status IS NOT NULL GROUP BY o.validity_status", p), ("valid", "expiring", "expired"))
    discovery["not_yet_valid"] = conn.execute(f"SELECT COALESCE(SUM(o.not_yet_valid = 1), 0) FROM fs_observations AS o WHERE {scope}", p).fetchone()[0]
    discovery_buckets = _counts(conn.execute(
        f"SELECT {_BUCKET_SQL.format(d='o.days_to_expiry')}, COUNT(*) FROM fs_observations AS o WHERE {scope} "
        f"AND o.days_to_expiry IS NOT NULL GROUP BY 1", p), EXPIRY_BUCKETS)

    now_unique = {"valid": 0, "expiring": 0, "expired": 0, "not_yet_valid": 0}
    now_sightings = dict(now_unique)
    buckets_unique, buckets_sightings = dict.fromkeys(EXPIRY_BUCKETS, 0), dict.fromkeys(EXPIRY_BUCKETS, 0)
    for cert in conn.execute(f"SELECT c.not_before, c.not_after, COUNT(*) AS sightings FROM fs_observations AS o "
                             f"JOIN certificates AS c ON c.sha256 = o.sha256 WHERE {scope} GROUP BY o.sha256", p):
        status, days, not_yet_valid = assess_at(cert["not_before"], cert["not_after"], now, threshold)
        bucket = expiry_bucket(days)
        for counts, buckets, weight in ((now_unique, buckets_unique, 1), (now_sightings, buckets_sightings, cert["sightings"])):
            counts[status] += weight
            buckets[bucket] += weight
            counts["not_yet_valid"] += weight if not_yet_valid else 0

    certs = f"FROM fs_observations AS o JOIN certificates AS c ON c.sha256 = o.sha256 WHERE {scope}"
    algorithms = _ranked(conn, f"SELECT c.key_algorithm AS key_algorithm, c.key_size AS key_size, c.key_curve AS key_curve, "
                               f"COUNT(DISTINCT o.sha256) AS uniq, COUNT(*) AS sightings {certs} "
                               f"GROUP BY c.key_algorithm, c.key_size, c.key_curve", p,
                         ORDER_ALGORITHMS, top_n, ("uniq", "sightings"))
    signatures = _ranked(conn, f"SELECT c.signature_algorithm AS signature_algorithm, COUNT(DISTINCT o.sha256) AS uniq, "
                               f"COUNT(*) AS sightings {certs} GROUP BY c.signature_algorithm", p,
                         ORDER_SIGNATURES, top_n, ("uniq", "sightings"))
    issuers = _ranked(conn, f"SELECT c.issuer AS issuer, COUNT(DISTINCT o.sha256) AS uniq, COUNT(*) AS sightings {certs} "
                            f"GROUP BY c.issuer", p, ORDER_ISSUERS, top_n, ("uniq", "sightings"))
    roots = _ranked(conn, f"SELECT o.scan_root AS scan_root, COUNT(*) AS observations, COALESCE(SUM(o.sha256 IS NOT NULL), 0) AS sightings, "
                          f"COUNT(DISTINCT o.sha256) AS uniq FROM fs_observations AS o WHERE {scope} GROUP BY o.scan_root", p,
                    ORDER_SCAN_ROOTS, MAX_TOP, ("observations", "sightings"))
    directories = _ranked(conn, f"SELECT rtrim(o.path, replace(o.path, '\\', '')) AS directory, COUNT(*) AS sightings, "
                                f"COUNT(DISTINCT o.sha256) AS uniq FROM fs_observations AS o WHERE {scope} AND o.sha256 IS NOT NULL "
                                f"GROUP BY 1", p, ORDER_DIRECTORIES, top_n, ("sightings",))

    status_params = {f"status{i}": status for i, status in enumerate(FILE_ERROR_STATUSES)}
    status_marks = ", ".join(f":{name}" for name in status_params)
    file_errors = conn.execute(f"SELECT COUNT(*) FROM fs_observations AS o WHERE {scope} AND o.parse_status IN ({status_marks})",
                               {**p, **status_params}).fetchone()[0]
    kinds = ", ".join("?" * len(DIRECTORY_LEVEL_ERROR_KINDS))
    directory_errors = conn.execute(f"SELECT COUNT(*) FROM run_issues WHERE run_id = ? AND source = 'agent' AND kind IN ({kinds})",
                                    (run_id, *DIRECTORY_LEVEL_ERROR_KINDS)).fetchone()[0]
    unresolved = unresolved_read_errors(conn, run_id)
    rejected = conn.execute("SELECT COUNT(DISTINCT seq) FROM run_issues WHERE run_id = ? AND source = 'backend' AND kind = 'rejected_record'",
                            (run_id,)).fetchone()[0]
    conflicts = conn.execute("SELECT COUNT(DISTINCT seq) FROM run_issues WHERE run_id = ? AND source = 'backend' AND kind = 'seq_conflict'",
                             (run_id,)).fetchone()[0]

    return {
        "run": {"run_id": run["run_id"], "run_number": run["run_number"], "type": run["type"], "status": run["status"],
                "final": run["status"] in rs.TERMINAL, "started_at": run["started_at"], "finished_at": run["finished_at"]},
        "as_of": _timestamp(now), "frontier": frontier, "frontier_scope": FRONTIER_SCOPE,
        "expiring_days": {"value": threshold, "source": threshold_source},
        "totals": {"records": row["records"], "sightings": row["sightings"], "unique_certificates": row["uniq"],
                   "duplicate_observations": {"total": row["sightings"] - row["uniq"], "within_file": within, "across_files": across},
                   "parse_failures": sum(by_status[s] for s in FAILURE_STATUSES), "no_certificate": by_status["no_certificate"],
                   "skipped": by_status["skipped"]},
        "parse_status": by_status, "formats": by_format,
        "validity": {"at_discovery": discovery, "now": {"unique": now_unique, "sightings": now_sightings}},
        "expiry_buckets": {"definitions": list(EXPIRY_BUCKETS), "at_discovery": discovery_buckets,
                           "now": {"unique": buckets_unique, "sightings": buckets_sightings}},
        "algorithms": algorithms, "signature_algorithms": signatures, "issuers": issuers,
        "locations": {"scan_roots": roots, "directories": directories},
        "issues": {"errors": {"total": file_errors + directory_errors + unresolved, "file_errors": file_errors,
                              "directory_errors": directory_errors, "unresolved_read_errors": unresolved},
                   "rejected": rejected, "seq_conflicts": conflicts},
    }


# ------------------------------------------------------------------ run statistics
_RUN_COLUMNS = ("run_id, run_number, type, run_trigger, status, queued_at, started_at, finished_at, duration_ms, stop_reason, "
                "cancel_requested, record_count, finding_count, rejected_count, error_count, error_summary")


def _brief(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["trigger"] = out.pop("run_trigger")
    out["cancel_requested"] = bool(out["cancel_requested"])
    return out


def run_statistics(conn: sqlite3.Connection, *, run_type: str | None = None, since: str | None = None,
                   limit: int = MAX_SERIES) -> dict:
    """Run history for charts: counts by type and status, and a bounded series of the most recent runs (oldest first).

    `since` keeps runs queued at or after that run timestamp ('YYYY-MM-DDTHH:MM:SS[.mmm]Z'). The series holds at most
    `limit` (<= 200) runs; the counts cover every matching run.
    """
    limit = _check_int("limit", limit, 1, MAX_SERIES)
    if run_type is not None and (not isinstance(run_type, str) or run_type not in RUN_TYPES):
        raise InvalidQuery("type", "unknown_value" if isinstance(run_type, str) else "wrong_type")
    if since is not None:
        if not isinstance(since, str):
            raise InvalidQuery("since", "wrong_type")
        if not _SINCE.fullmatch(since):
            raise InvalidQuery("since", "not_a_run_timestamp")
        since = since if "." in since else since[:-1] + ".000Z"            # compare like with like (stored values carry milliseconds)
    prepare_snapshot(conn)
    p = {"type": run_type, "since": since, "limit": limit}
    where = "(:type IS NULL OR type = :type) AND (:since IS NULL OR queued_at >= :since)"
    groups = [{"type": r[0], "status": r[1], "count": r[2]} for r in conn.execute(
        f"SELECT type, status, COUNT(*) FROM runs WHERE {where} GROUP BY type, status ORDER BY type, status", p)]
    by_status = dict.fromkeys(rs.STATUSES, 0)
    for g in groups:
        by_status[g["status"]] += g["count"]
    series = [_brief(r) for r in conn.execute(
        f"SELECT * FROM (SELECT {_RUN_COLUMNS} FROM runs WHERE {where} ORDER BY run_number DESC LIMIT :limit) ORDER BY run_number ASC", p)]
    return {"by_type_status": groups, "totals": {"runs": sum(g["count"] for g in groups), "by_status": by_status},
            "series": series, "series_limit": limit}


# ------------------------------------------------------------------ dashboard
def dashboard(conn: sqlite3.Connection, *, now: dt.datetime, recent: int = DEFAULT_RECENT, top_n: int = DEFAULT_TOP) -> dict:
    """The opening screen: what was started last, what the newest finished filesystem scan found, and a short history.

    latest_run               highest run_number, any type, any status (what the user last started).
    latest_terminal_fs_run   among filesystem runs that have ended (completed / partial / failed), the one that FINISHED
                             last (ties: higher run_number). Its summary is `summary`; nothing is substituted for it.
    """
    now = _check_now(now)
    recent = _check_int("recent", recent, 1, 100)
    top_n = _check_int("top_n", top_n, 1, MAX_TOP)             # checked here too: an empty database never reaches fs_summary
    prepare_snapshot(conn)
    latest = conn.execute(f"SELECT {_RUN_COLUMNS} FROM runs ORDER BY run_number DESC LIMIT 1").fetchone()
    terminal = ", ".join(f"'{status}'" for status in sorted(rs.TERMINAL))
    finished = conn.execute(f"SELECT {_RUN_COLUMNS} FROM runs WHERE type = 'filesystem' AND status IN ({terminal}) "
                            f"ORDER BY finished_at DESC, run_number DESC LIMIT 1").fetchone()
    by_status = dict.fromkeys(rs.STATUSES, 0)
    for status, count in conn.execute("SELECT status, COUNT(*) FROM runs GROUP BY status"):
        by_status[status] = count
    recent_rows = conn.execute(f"SELECT {_RUN_COLUMNS} FROM runs ORDER BY run_number DESC LIMIT ?", (recent,)).fetchall()
    return {"as_of": _timestamp(now),
            "latest_run": None if latest is None else _brief(latest),
            "latest_terminal_fs_run": None if finished is None else _brief(finished),
            "summary": None if finished is None else fs_summary(conn, finished["run_id"], now=now, top_n=top_n),
            "runs_by_status": by_status, "recent_runs": [_brief(r) for r in recent_rows]}
