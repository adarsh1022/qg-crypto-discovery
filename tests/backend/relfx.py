"""Fixtures and an INDEPENDENT oracle for relationship tests.

The oracle never reads the database and never calls backend/relationships.py: it derives the edges a run must have from the
records that were fed into ingestion, using the rules written out in the Phase 3 design (not the SQL the module uses).
`stored()` reads edge_runs with its own SQL, so a bug shared by recording and reading cannot make both agree by accident.
"""
import ingestfx
import tlsingestfx
from backend import db, fs_ingest, runs, service
from ingestfx import NOW, at

HOST = "agent-1"


def add_host(conn, host_id=HOST, hostname="WORKSTATION"):
    runs.register_host(conn, host_id, hostname, now=NOW)


def finish_in_service(conn, run_id, **kwargs):
    """Finalize exactly the way the service does (the path that records relationships)."""
    with db.transaction(conn):
        return service._finalize_in_tx(conn, run_id, now=at(10), **kwargs)


def fs_run(conn, records, *, host_id=HOST, finalize=True, **finish):
    add_host(conn, host_id)
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.start_run(conn, run_id, now=at(1), host_id=host_id)
    if records:
        ingestfx.ingest(conn, run_id, records)
    if finalize:
        finish.setdefault("outcome", "finished")
        if finish["outcome"] == "finished":
            finish.setdefault("summary", ingestfx.summary(len(records)))
        finish_in_service(conn, run_id, **finish)
    return run_id


def tls_run(conn, records, *, host_id=HOST, finalize=True, **finish):
    add_host(conn, host_id)
    run_id = runs.create_run(conn, "tls", "manual", now=NOW)
    runs.start_run(conn, run_id, now=at(1), host_id=host_id)
    if records:
        tlsingestfx.ingest(conn, run_id, records)
    if finalize:
        finish.setdefault("outcome", "finished")
        if finish["outcome"] == "finished":
            finish.setdefault("summary", tlsingestfx.tls_summary(len(records)))
        finish_in_service(conn, run_id, **finish)
    return run_id


# ------------------------------------------------------------------ the oracle (from INPUT records only)
def oracle_fs(records, host_id=HOST):
    """{(kind, src_kind, src_key, dst_kind, dst_key): supporting observations}"""
    expected = {}
    for record in records:
        if record["parse_status"] == "ok":
            key = ("stored_on", "certificate", record["sha256"], "host", host_id)
            expected[key] = expected.get(key, 0) + 1
    return expected


def oracle_tls(records, host_id=HOST):
    expected = {}
    for record in records:
        if record["handshake_outcome"] != "completed":
            continue
        endpoint = f'{host_id}|{record["dst_ip"]}:{record["dst_port"]}/tcp'
        for sha in {peer["sha256"] for peer in record["peer_certificates"]}:     # a certificate twice in one chain is one observation
            key = ("presented_certificate", "endpoint", endpoint, "certificate", sha)
            expected[key] = expected.get(key, 0) + 1
    return expected


# ------------------------------------------------------------------ what is actually stored (own SQL)
def stored(conn, run_id):
    rows = conn.execute(
        "SELECT e.kind, s.kind, s.node_key, d.kind, d.node_key, er.observation_count FROM edge_runs er, edges e, nodes s, nodes d "
        "WHERE er.run_id = ? AND e.edge_id = er.edge_id AND s.node_id = e.src_node AND d.node_id = e.dst_node", (run_id,)).fetchall()
    return {tuple(row[:5]): row[5] for row in rows}


def table_snapshot(conn):
    return {name: sorted(tuple(r) for r in conn.execute(f"SELECT * FROM {name}")) for name in ("nodes", "edges", "edge_runs")}


def check_invariants(conn):
    """Every edge's totals are exactly the sum of its runs' contributions, and no edge exists without a contribution."""
    bad = conn.execute(
        "SELECT e.edge_id FROM edges e LEFT JOIN (SELECT edge_id, SUM(observation_count) AS n, COUNT(*) AS r FROM edge_runs GROUP BY edge_id) x "
        "ON x.edge_id = e.edge_id WHERE x.edge_id IS NULL OR e.observation_count <> x.n OR e.run_count <> x.r").fetchall()
    assert bad == [], f"edge totals disagree with edge_runs: {bad}"


def edge_kinds(conn):
    return {row[0] for row in conn.execute("SELECT DISTINCT kind FROM edges")}


def api_rows(items):
    """The public rows reduced to the oracle's shape, for comparison."""
    out = {}
    for item in items:
        if item["kind"] == "stored_on":
            key = ("stored_on", "certificate", item["source"]["sha256"], "host", item["target"]["host_id"])
        else:
            host = item["source"]["host"]["host_id"]
            key = ("presented_certificate", "endpoint", f'{host}|{item["source"]["label"]}', "certificate", item["target"]["sha256"])
        assert key not in out, "a relationship is listed twice"
        out[key] = item["in_run"]["observations"]
    return out
