"""Relationship recording and reading: what a finished run's stored evidence says about certificates, hosts and listeners.

What is recorded (and ONLY this; nothing is guessed, nothing comes from outside the run's own stored observations)
  stored_on              certificate -> host      a filesystem observation parsed this certificate from a file on the host that
                                                  ran the scan (parse_status 'ok'). It says the file exists there, not that the
                                                  certificate is in use.
  presented_certificate  endpoint -> certificate  a COMPLETED TLS handshake against a local listener returned this certificate in
                                                  its peer chain (one edge per certificate in the chain).

What is deliberately NOT recorded
  communicates_with      the schema allows host/process -> endpoint, but the agent only ACTIVELY PROBES listeners on this machine.
                         Nothing is observed communicating, so that kind would misdescribe the evidence. A probed listener is an
                         endpoint node scoped to the host that has it (key "<host_id>|<ip>:<port>/tcp", attrs scope=local_listener):
                         the host is part of the endpoint's identity, so two machines' 127.0.0.1:443 never merge.
  process nodes          a process is shown on a listener row at read time, only when every completed probe of that listener in
                         the run was attributed to the same process. It is never stored, and a PID never identifies anything.

One run, one contribution
  `edge_runs` holds each run's own contribution to an edge (its supporting observation rows). `edges.observation_count` is the sum
  of those, `edges.run_count` the number of runs, so repeating a scan strengthens an edge but never double counts a run.
  Recording is idempotent: an `edge_runs` row is inserted at most once per (edge, run), and the edge totals change only when a row
  was really inserted. Timestamps are second resolution, UTC.

Recording status (computed when read, from this run's own rows only, inside one read snapshot)
  pending        the run has not finished: nothing is recorded yet
  recorded       the run's stored contribution equals what its observations support
  none_expected  the run's observations support no relationship, and none is stored
  incomplete     they differ (older runs, from before recording existed, land here: `missing` > 0 and `unexpected` = 0)
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from . import db, run_state as rs, runs
from .fs_record import canonical_json
from .reports import _int, prepare_snapshot

DEFAULT_LIMIT = 200
MAX_LIMIT = 500
MAX_CROSS_HOSTS = 5                         # filesystem sightings listed per certificate on a listener row

STORED_ON = "stored_on"
PRESENTED = "presented_certificate"
KINDS = (STORED_ON, PRESENTED)
LABELS = {
    STORED_ON: "Certificate parsed from a file on this host",
    PRESENTED: "Certificate presented by a local listener (active probe)",
}
ENDPOINT_SCOPE = "local_listener"
PENDING, RECORDED, NONE_EXPECTED, INCOMPLETE = "pending", "recorded", "none_expected", "incomplete"


@dataclass(frozen=True)
class EdgeKey:
    kind: str
    src_kind: str
    src_key: str
    dst_kind: str
    dst_key: str


@dataclass(frozen=True)
class Expected:
    """One edge a run's own stored observations support, with its supporting-row count and the nodes' labels and attributes."""
    src_label: str
    dst_label: str
    src_attrs: str
    observations: int
    first_at: str
    last_at: str


def endpoint_key(host_id: str, ip: str, port: int) -> str:
    return f"{host_id}|{ip}:{port}/tcp"


# ------------------------------------------------------------------ what the evidence supports (shared by recording and reading)
def _run_facts(conn: sqlite3.Connection, run_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT run_id, run_number, type, status, host_id FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise runs.RunNotFound(run_id)
    return row


def expected_edges(conn: sqlite3.Connection, run_id: str, *, budget: db.QueryBudget | None = None) -> dict[EdgeKey, Expected]:
    """Every edge the run's stored observations support. A run with no host (never claimed) supports none."""
    run = _run_facts(conn, run_id)
    host_id = run["host_id"]
    if host_id is None:
        return {}
    host_label = conn.execute("SELECT hostname FROM hosts WHERE host_id = ?", (host_id,)).fetchone()[0]
    found: dict[EdgeKey, Expected] = {}
    if run["type"] == "filesystem":
        rows = conn.execute(
            "SELECT o.sha256, c.subject, COUNT(*) AS n, MIN(o.discovered_at) AS first_at, MAX(o.discovered_at) AS last_at "
            "FROM fs_observations o JOIN certificates c ON c.sha256 = o.sha256 "
            "WHERE o.run_id = ? AND o.parse_status = 'ok' AND o.sha256 IS NOT NULL GROUP BY o.sha256 ORDER BY o.sha256", (run_id,))
        for row in rows:
            key = EdgeKey(STORED_ON, "certificate", row["sha256"], "host", host_id)
            found[key] = Expected(row["subject"], host_label, "{}", row["n"], row["first_at"], row["last_at"])
    elif run["type"] == "tls":
        rows = conn.execute(
            "SELECT o.dst_ip, o.dst_port, p.sha256, c.subject, COUNT(DISTINCT o.id) AS n, "
            "       MIN(substr(o.observed_at, 1, 19) || 'Z') AS first_at, MAX(substr(o.observed_at, 1, 19) || 'Z') AS last_at "
            "FROM tls_observations o JOIN tls_peer_certificates p ON p.tls_observation_id = o.id "
            "JOIN certificates c ON c.sha256 = p.sha256 "
            "WHERE o.run_id = ? AND o.handshake_outcome = 'completed' "
            "GROUP BY o.dst_ip, o.dst_port, p.sha256 ORDER BY o.dst_ip, o.dst_port, p.sha256", (run_id,))
        for row in rows:
            key = EdgeKey(PRESENTED, "endpoint", endpoint_key(host_id, row["dst_ip"], row["dst_port"]), "certificate", row["sha256"])
            attrs = canonical_json({"host_id": host_id, "scope": ENDPOINT_SCOPE})
            found[key] = Expected(f'{row["dst_ip"]}:{row["dst_port"]}/tcp', row["subject"], attrs, row["n"], row["first_at"], row["last_at"])
    if budget is not None:
        budget.check()
    return found


# ------------------------------------------------------------------ recording (inside the finalization transaction)
def _node(conn: sqlite3.Connection, kind: str, key: str, label: str, attrs: str, first_at: str, last_at: str) -> int:
    conn.execute(
        "INSERT INTO nodes (kind, node_key, label, attrs_json, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (kind, node_key) DO UPDATE SET first_seen_at = MIN(first_seen_at, excluded.first_seen_at), "
        "last_seen_at = MAX(last_seen_at, excluded.last_seen_at)", (kind, key, label, attrs, first_at, last_at))
    return conn.execute("SELECT node_id FROM nodes WHERE kind = ? AND node_key = ?", (kind, key)).fetchone()[0]


def record_run_in_tx(conn: sqlite3.Connection, run_id: str) -> int:
    """Record what a FINISHED run's observations support. Returns how many (edge, run) contributions were newly stored.

    Idempotent: running it again (a retry, a second finalization attempt) stores nothing and changes no total. The caller owns
    the transaction and decides what a failure means (service wraps this in a savepoint so it cannot undo the finalization).
    """
    db.require_transaction(conn)
    run = _run_facts(conn, run_id)
    if run["status"] not in rs.TERMINAL:
        raise ValueError("only a finished run can be recorded")
    inserted = 0
    for key, edge in expected_edges(conn, run_id).items():
        src = _node(conn, key.src_kind, key.src_key, edge.src_label, edge.src_attrs, edge.first_at, edge.last_at)
        dst = _node(conn, key.dst_kind, key.dst_key, edge.dst_label, "{}", edge.first_at, edge.last_at)
        found = conn.execute("SELECT edge_id FROM edges WHERE src_node = ? AND dst_node = ? AND kind = ?", (src, dst, key.kind)).fetchone()
        if found is None:
            edge_id = conn.execute(
                "INSERT INTO edges (src_node, dst_node, kind, observation_count, run_count, first_seen_at, last_seen_at) "
                "VALUES (?, ?, ?, ?, 1, ?, ?)", (src, dst, key.kind, edge.observations, edge.first_at, edge.last_at)).lastrowid
            conn.execute("INSERT INTO edge_runs (edge_id, run_id, observation_count, first_at, last_at) VALUES (?, ?, ?, ?, ?)",
                         (edge_id, run_id, edge.observations, edge.first_at, edge.last_at))
            inserted += 1
            continue
        edge_id = found[0]
        added = conn.execute(
            "INSERT INTO edge_runs (edge_id, run_id, observation_count, first_at, last_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (edge_id, run_id) DO NOTHING", (edge_id, run_id, edge.observations, edge.first_at, edge.last_at)).rowcount
        if added:                                                    # totals move only when this run's row is really new
            conn.execute(
                "UPDATE edges SET observation_count = observation_count + ?, run_count = run_count + 1, "
                "first_seen_at = MIN(first_seen_at, ?), last_seen_at = MAX(last_seen_at, ?) WHERE edge_id = ?",
                (edge.observations, edge.first_at, edge.last_at, edge_id))
            inserted += 1
    return inserted


def record_run(conn: sqlite3.Connection, run_id: str) -> int:
    """`record_run_in_tx` in its own transaction (for callers outside a finalization, such as tests)."""
    with db.transaction(conn):
        return record_run_in_tx(conn, run_id)


# ------------------------------------------------------------------ reading
_STORED_KEYS = (
    "SELECT e.kind AS kind, s.kind AS src_kind, s.node_key AS src_key, d.kind AS dst_kind, d.node_key AS dst_key, "
    "       er.observation_count AS n "
    "FROM edge_runs er JOIN edges e ON e.edge_id = er.edge_id JOIN nodes s ON s.node_id = e.src_node "
    "JOIN nodes d ON d.node_id = e.dst_node WHERE er.run_id = ?")


def recording_state(expected: dict[EdgeKey, Expected], stored: dict[EdgeKey, int], final: bool) -> dict:
    """Compare THIS run's stored contribution with what its observations support. Edge totals (other runs) play no part."""
    if not final:
        return {"state": PENDING, "expected": 0, "recorded": len(stored), "missing": 0, "unexpected": 0}
    missing = sum(1 for k, e in expected.items() if stored.get(k) != e.observations)
    unexpected = sum(1 for k in stored if k not in expected)
    if missing == 0 and unexpected == 0:
        state = RECORDED if expected else NONE_EXPECTED
    else:
        state = INCOMPLETE
    return {"state": state, "expected": len(expected), "recorded": len(stored), "missing": missing, "unexpected": unexpected}


def _process_by_listener(conn: sqlite3.Connection, run_id: str) -> dict[tuple[str, int], dict | None]:
    """The one process behind each probed listener, or None when any completed probe was unattributed or they disagree."""
    seen: dict[tuple[str, int], set] = {}
    for row in conn.execute("SELECT dst_ip, dst_port, process_attribution, process_name, exe_path FROM tls_observations "
                            "WHERE run_id = ? AND handshake_outcome = 'completed'", (run_id,)):
        seen.setdefault((row["dst_ip"], row["dst_port"]), set()).add((row["process_attribution"], row["process_name"], row["exe_path"]))
    result: dict[tuple[str, int], dict | None] = {}
    for listener, facts in seen.items():
        only = next(iter(facts)) if len(facts) == 1 else None
        result[listener] = {"name": only[1], "exe_path": only[2]} if only and only[0] == "attributed" and only[1] else None
    return result


def _filesystem_evidence(conn: sqlite3.Connection, shas: list[str]) -> dict[str, dict]:
    """For certificates shown on listener rows: where filesystem scans (any run) stored the same certificate, by SHA-256."""
    if not shas:
        return {}
    marks = ",".join("?" * len(shas))
    rows = conn.execute(
        f"SELECT c.node_key AS sha256, h.node_key AS host_id, h.label AS hostname, e.observation_count AS observations, "
        f"       e.run_count AS runs, e.last_seen_at AS last_seen_at, "
        f"       (SELECT r.run_number FROM edge_runs er JOIN runs r ON r.run_id = er.run_id WHERE er.edge_id = e.edge_id "
        f"        ORDER BY r.run_number DESC LIMIT 1) AS latest_run_number, "
        f"       (SELECT r.run_id FROM edge_runs er JOIN runs r ON r.run_id = er.run_id WHERE er.edge_id = e.edge_id "
        f"        ORDER BY r.run_number DESC LIMIT 1) AS latest_run_id "
        f"FROM edges e JOIN nodes c ON c.node_id = e.src_node AND c.kind = 'certificate' JOIN nodes h ON h.node_id = e.dst_node "
        f"WHERE e.kind = 'stored_on' AND c.node_key IN ({marks}) ORDER BY c.node_key, e.last_seen_at DESC, h.label, h.node_key", shas)
    found: dict[str, dict] = {}
    for row in rows:
        entry = found.setdefault(row["sha256"], {"hosts": [], "omitted": 0})
        if len(entry["hosts"]) >= MAX_CROSS_HOSTS:
            entry["omitted"] += 1
            continue
        entry["hosts"].append({"host_id": row["host_id"], "hostname": row["hostname"], "observations": row["observations"],
                               "runs": row["runs"], "last_seen_at": row["last_seen_at"],
                               "latest_run_id": row["latest_run_id"], "latest_run_number": row["latest_run_number"]})
    return found


def get_relationships(conn: sqlite3.Connection, run_id: str, *, limit: int = DEFAULT_LIMIT, budget: db.QueryBudget | None = None) -> dict:
    """The run's recorded relationships (bounded, deterministic order) and whether recording matches its evidence."""
    limit = _int("limit", limit, 1, MAX_LIMIT)
    if limit is None:
        limit = DEFAULT_LIMIT
    prepare_snapshot(conn)
    run = _run_facts(conn, run_id)
    final = run["status"] in rs.TERMINAL
    stored = {EdgeKey(r["kind"], r["src_kind"], r["src_key"], r["dst_kind"], r["dst_key"]): r["n"]
              for r in conn.execute(_STORED_KEYS, (run_id,))}
    state = recording_state(expected_edges(conn, run_id, budget=budget) if final else {}, stored, final)
    counts = {kind: 0 for kind in KINDS}
    for key in stored:
        counts[key.kind] += 1
    rows = conn.execute(
        "SELECT e.kind AS kind, e.observation_count AS total_observations, e.run_count AS run_count, e.first_seen_at AS first_seen_at, "
        "       e.last_seen_at AS last_seen_at, er.observation_count AS observations, er.first_at AS run_first_at, er.last_at AS run_last_at, "
        "       s.kind AS src_kind, s.node_key AS src_key, s.label AS src_label, s.attrs_json AS src_attrs, "
        "       d.kind AS dst_kind, d.node_key AS dst_key, d.label AS dst_label, "
        "       sh.hostname AS endpoint_hostname, dh.hostname AS target_hostname "
        "FROM edge_runs er JOIN edges e ON e.edge_id = er.edge_id JOIN nodes s ON s.node_id = e.src_node "
        "JOIN nodes d ON d.node_id = e.dst_node "
        "LEFT JOIN hosts sh ON s.kind = 'endpoint' AND sh.host_id = json_extract(s.attrs_json, '$.host_id') "
        "LEFT JOIN hosts dh ON d.kind = 'host' AND dh.host_id = d.node_key "
        "WHERE er.run_id = ? ORDER BY e.kind, s.label, d.label, e.edge_id LIMIT ?", (run_id, limit)).fetchall()
    if budget is not None:
        budget.check()
    processes = _process_by_listener(conn, run_id) if run["type"] == "tls" else {}
    cross = _filesystem_evidence(conn, sorted({r["dst_key"] for r in rows if r["kind"] == PRESENTED}))
    items = []
    for r in rows:
        item: dict[str, Any] = {
            "kind": r["kind"], "label": LABELS[r["kind"]],
            "in_run": {"observations": r["observations"], "first_at": r["run_first_at"], "last_at": r["run_last_at"]},
            "all_runs": {"observations": r["total_observations"], "runs": r["run_count"],
                         "first_seen_at": r["first_seen_at"], "last_seen_at": r["last_seen_at"]},
            "process": None, "filesystem_evidence": None,
        }
        if r["kind"] == STORED_ON:
            item["source"] = {"kind": "certificate", "label": r["src_label"], "sha256": r["src_key"]}
            item["target"] = {"kind": "host", "label": r["dst_label"], "host_id": r["dst_key"]}
        else:
            ip_port = r["src_key"].rsplit("|", 1)[1][: -len("/tcp")]
            ip, port = ip_port.rsplit(":", 1)
            host_id = r["src_key"].rsplit("|", 1)[0]
            item["source"] = {"kind": "endpoint", "label": r["src_label"], "scope": ENDPOINT_SCOPE,
                              "host": {"host_id": host_id, "hostname": r["endpoint_hostname"]}}
            item["target"] = {"kind": "certificate", "label": r["dst_label"], "sha256": r["dst_key"]}
            item["process"] = processes.get((ip, int(port)))
            item["filesystem_evidence"] = cross.get(r["dst_key"], {"hosts": [], "omitted": 0})
        items.append(item)
    return {"run": {"run_id": run["run_id"], "run_number": run["run_number"], "type": run["type"], "status": run["status"], "final": final},
            "recording": state, "counts": counts,
            "items": items, "total": len(stored), "limit": limit, "truncated": len(stored) > len(items)}
