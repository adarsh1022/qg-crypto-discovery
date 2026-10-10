"""Relationship recording and reading, checked against an independent oracle (relfx): creation, run isolation, idempotency,
missing evidence, process association and cross-source evidence. No relationship is ever created from anything but a run's own
stored observations."""
import pytest

import ingestfx
import relfx
import tlsingestfx
from backend import db, relationships, runs
from ingestfx import failure_record, ok_record, pfx_record
from tlsingestfx import failed_record, peer, tls_record


def read(conn, run_id, **kw):
    with db.read_snapshot(conn):
        return relationships.get_relationships(conn, run_id, **kw)


def state(conn, run_id):
    return read(conn, run_id)["recording"]


# ------------------------------------------------------------------ filesystem: stored_on
def fs_dataset():
    return [
        ok_record(r"C:\app\a.pem", 1),
        ok_record(r"C:\app\b.pem", 1),                 # the same certificate in a second file: one edge, two observations
        ok_record(r"C:\app\c.pem", 2),
        pfx_record(r"C:\app\bundle.pfx", 3),
        failure_record(r"C:\app\locked.pem"),          # access denied: no certificate, no relationship
        failure_record(r"C:\app\bad.pem", status="malformed"),
        failure_record(r"C:\app\none.pem", status="no_certificate"),
    ]


def test_a_filesystem_run_records_exactly_what_the_oracle_says(conn):
    records = fs_dataset()
    run_id = relfx.fs_run(conn, records)
    expected = relfx.oracle_fs(records)
    assert expected and len(expected) == 3
    assert relfx.stored(conn, run_id) == expected
    page = read(conn, run_id)
    assert relfx.api_rows(page["items"]) == expected
    assert page["recording"] == {"state": "recorded", "expected": 3, "recorded": 3, "missing": 0, "unexpected": 0}
    assert page["counts"] == {"stored_on": 3, "presented_certificate": 0}
    relfx.check_invariants(conn)


def test_stored_on_goes_from_the_certificate_to_the_host_that_ran_the_scan(conn):
    run_id = relfx.fs_run(conn, [ok_record(r"C:\app\a.pem", 1)], host_id="host-x")
    item = read(conn, run_id)["items"][0]
    assert item["kind"] == "stored_on" and "file" in item["label"]
    assert item["source"] == {"kind": "certificate", "label": "CN=cert1", "sha256": ingestfx.sha(1)}
    assert item["target"]["kind"] == "host" and item["target"]["host_id"] == "host-x" and item["target"]["label"] == "WORKSTATION"
    assert item["process"] is None and item["filesystem_evidence"] is None


def test_the_graph_holds_only_the_two_recorded_kinds_and_correct_node_kinds(conn):
    relfx.fs_run(conn, fs_dataset())
    relfx.tls_run(conn, [tls_record(7, port=8443)])
    assert relfx.edge_kinds(conn) == {"stored_on", "presented_certificate"}          # never communicates_with
    assert {r[0] for r in conn.execute("SELECT DISTINCT kind FROM nodes")} == {"certificate", "host", "endpoint"}   # never process
    for src, dst, kind in conn.execute("SELECT s.kind, d.kind, e.kind FROM edges e JOIN nodes s ON s.node_id = e.src_node JOIN nodes d ON d.node_id = e.dst_node"):
        assert (src, dst) == (("certificate", "host") if kind == "stored_on" else ("endpoint", "certificate"))


# ------------------------------------------------------------------ TLS: presented_certificate
def tls_dataset():
    return [
        tls_record(1, port=8443, peers=[peer(1), peer(2), peer(3)]),                 # a three-certificate chain
        tls_record(1, port=8443, peers=[peer(1), peer(2), peer(3)]),                 # probed again: counts as a second observation
        tls_record(4, port=9443),
        tls_record(5, port=7443, peers=[peer(5), peer(5)]),                          # the same certificate twice in ONE chain
        failed_record(port=9000),                                                    # failed: not a relationship
        failed_record(port=9001, outcome="incomplete"),
        failed_record(port=9002, outcome="alert"),
        tls_record(6, port=6443, peers=[]),                                          # completed, but no certificate was returned
    ]


def test_a_tls_run_records_exactly_what_the_oracle_says(conn):
    records = tls_dataset()
    run_id = relfx.tls_run(conn, records)
    expected = relfx.oracle_tls(records)
    assert len(expected) == 3 + 1 + 1
    assert relfx.stored(conn, run_id) == expected
    page = read(conn, run_id)
    assert relfx.api_rows(page["items"]) == expected
    assert page["recording"]["state"] == "recorded" and page["counts"] == {"stored_on": 0, "presented_certificate": 5}
    relfx.check_invariants(conn)


def test_a_listener_is_a_host_scoped_endpoint_not_a_communication(conn):
    run_id = relfx.tls_run(conn, [tls_record(1, port=8443)])
    item = read(conn, run_id)["items"][0]
    assert item["kind"] == "presented_certificate" and "active probe" in item["label"] and "local listener" in item["label"]
    assert item["source"]["kind"] == "endpoint" and item["source"]["label"] == "127.0.0.1:8443/tcp"
    assert item["source"]["scope"] == "local_listener" and item["source"]["host"] == {"host_id": "agent-1", "hostname": "WORKSTATION"}
    node = conn.execute("SELECT node_key, attrs_json FROM nodes WHERE kind = 'endpoint'").fetchone()
    assert node["node_key"] == "agent-1|127.0.0.1:8443/tcp"
    assert '"scope":"local_listener"' in node["attrs_json"].replace(" ", "")


def test_two_machines_with_the_same_loopback_listener_never_merge(conn):
    a = relfx.tls_run(conn, [tls_record(1, port=443)], host_id="host-a")
    b = relfx.tls_run(conn, [tls_record(2, port=443)], host_id="host-b")
    assert conn.execute("SELECT COUNT(*) FROM nodes WHERE kind = 'endpoint'").fetchone()[0] == 2
    assert set(relfx.stored(conn, a)) == set(relfx.oracle_tls([tls_record(1, port=443)], "host-a"))
    assert set(relfx.stored(conn, b)) == set(relfx.oracle_tls([tls_record(2, port=443)], "host-b"))
    assert not set(relfx.stored(conn, a)) & set(relfx.stored(conn, b))


# ------------------------------------------------------------------ run isolation and repeated observations
def test_repeating_a_scan_strengthens_the_edge_and_each_run_keeps_its_own_contribution(conn):
    first = relfx.fs_run(conn, [ok_record(r"C:\app\a.pem", 1), ok_record(r"C:\app\b.pem", 1)])
    second = relfx.fs_run(conn, [ok_record(r"C:\app\a.pem", 1)])
    edge = conn.execute("SELECT observation_count, run_count FROM edges").fetchone()
    assert (edge["observation_count"], edge["run_count"]) == (3, 2)
    assert list(relfx.stored(conn, first).values()) == [2] and list(relfx.stored(conn, second).values()) == [1]
    one, two = read(conn, first)["items"][0], read(conn, second)["items"][0]
    assert one["in_run"]["observations"] == 2 and two["in_run"]["observations"] == 1
    assert one["all_runs"]["observations"] == two["all_runs"]["observations"] == 3
    assert one["all_runs"]["runs"] == two["all_runs"]["runs"] == 2
    relfx.check_invariants(conn)


def test_one_run_cannot_make_another_run_look_recorded(conn):
    recorded = relfx.fs_run(conn, [ok_record(r"C:\app\a.pem", 1)])
    # the second run has the SAME evidence but is finalized without the service, so it was never recorded
    relfx.add_host(conn)
    run_id = runs.create_run(conn, "filesystem", "manual", now=ingestfx.NOW)
    runs.start_run(conn, run_id, now=ingestfx.at(1), host_id=relfx.HOST)
    ingestfx.ingest(conn, run_id, [ok_record(r"C:\app\a.pem", 1)])
    ingestfx.finish(conn, run_id, 1)
    assert state(conn, recorded)["state"] == "recorded"
    unrecorded = state(conn, run_id)
    assert unrecorded == {"state": "incomplete", "expected": 1, "recorded": 0, "missing": 1, "unexpected": 0}   # "not recorded for this run"
    assert read(conn, run_id)["items"] == []
    relfx.check_invariants(conn)


def test_a_run_without_evidence_reads_none_expected_even_if_the_graph_has_edges(conn):
    relfx.fs_run(conn, [ok_record(r"C:\app\a.pem", 1)])
    empty = relfx.fs_run(conn, [])
    only_failures = relfx.fs_run(conn, [failure_record()])
    for run_id in (empty, only_failures):
        page = read(conn, run_id)
        assert page["recording"] == {"state": "none_expected", "expected": 0, "recorded": 0, "missing": 0, "unexpected": 0}
        assert page["items"] == [] and page["total"] == 0 and page["truncated"] is False


def test_unfinished_runs_are_pending_and_record_nothing(conn):
    relfx.add_host(conn)
    queued = runs.create_run(conn, "filesystem", "manual", now=ingestfx.NOW)
    running = relfx.fs_run(conn, [ok_record(r"C:\app\a.pem", 1)], finalize=False)
    for run_id in (queued, running):
        page = read(conn, run_id)
        assert page["recording"]["state"] == "pending" and page["items"] == [] and page["run"]["final"] is False
    assert conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0] == 0
    with pytest.raises(ValueError):
        relationships.record_run(conn, running)
    assert conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] == 0


def test_an_unknown_run_is_not_found(conn):
    with pytest.raises(runs.RunNotFound):
        read(conn, "no-such-run")


# ------------------------------------------------------------------ idempotency and retries
def test_recording_again_changes_nothing(conn):
    run_id = relfx.tls_run(conn, tls_dataset())
    before = relfx.table_snapshot(conn)
    assert relationships.record_run(conn, run_id) == 0
    assert relationships.record_run(conn, run_id) == 0
    assert relfx.table_snapshot(conn) == before
    relfx.check_invariants(conn)


def test_a_retry_after_a_partial_failure_converges_without_double_counting(conn):
    """If the first attempt stored only some contributions, a retry stores the rest and leaves the stored ones alone."""
    records = [ok_record(r"C:\app\a.pem", 1), ok_record(r"C:\app\b.pem", 2)]
    run_id = relfx.fs_run(conn, records)
    with db.transaction(conn):                     # simulate a crash that kept only the first contribution
        edge_id = conn.execute("SELECT e.edge_id FROM edges e JOIN nodes s ON s.node_id = e.src_node WHERE s.node_key = ?",
                               (ingestfx.sha(2),)).fetchone()[0]
        conn.execute("DELETE FROM edge_runs WHERE edge_id = ?", (edge_id,))
        conn.execute("DELETE FROM edges WHERE edge_id = ?", (edge_id,))
    assert state(conn, run_id)["state"] == "incomplete"
    assert relationships.record_run(conn, run_id) == 1
    assert relfx.stored(conn, run_id) == relfx.oracle_fs(records)
    assert state(conn, run_id)["state"] == "recorded"
    relfx.check_invariants(conn)


# ------------------------------------------------------------------ outcomes of the run
@pytest.mark.parametrize("finish", [
    dict(outcome="failed", fatal_code="boom"),
    dict(outcome="lost"),
    dict(outcome="cancelled"),
])
def test_runs_that_did_not_finish_normally_still_record_what_was_stored(conn, finish):
    records = [ok_record(r"C:\app\a.pem", 1)]
    run_id = relfx.fs_run(conn, records, **finish)
    assert read(conn, run_id)["run"]["status"] in ("partial", "failed")
    assert relfx.stored(conn, run_id) == relfx.oracle_fs(records)
    assert state(conn, run_id)["state"] == "recorded"


def test_a_failed_run_with_nothing_stored_is_none_expected(conn):
    run_id = relfx.tls_run(conn, [], outcome="failed", fatal_code="boom")
    assert read(conn, run_id)["run"]["status"] == "failed" and state(conn, run_id)["state"] == "none_expected"


def test_a_run_that_never_had_a_host_supports_no_relationship(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=ingestfx.NOW)
    runs.start_run(conn, run_id, now=ingestfx.at(1))                          # no host_id
    ingestfx.ingest(conn, run_id, [ok_record(r"C:\app\a.pem", 1)])
    relfx.finish_in_service(conn, run_id, outcome="finished", summary=ingestfx.summary(1))
    assert state(conn, run_id)["state"] == "none_expected"
    assert conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] == 0


# ------------------------------------------------------------------ the comparison cannot be fooled by other runs or tampering
def test_status_compares_this_runs_rows_not_edge_totals(conn):
    a = relfx.fs_run(conn, [ok_record(r"C:\app\a.pem", 1)])
    for _ in range(3):
        relfx.fs_run(conn, [ok_record(r"C:\app\a.pem", 1)])
    assert state(conn, a)["state"] == "recorded"                              # edge totals grew to 4 runs; this run still agrees


def test_a_missing_changed_or_extra_contribution_is_incomplete(conn):
    run_id = relfx.fs_run(conn, [ok_record(r"C:\app\a.pem", 1), ok_record(r"C:\app\b.pem", 2)])
    assert state(conn, run_id)["state"] == "recorded"
    with db.transaction(conn):
        conn.execute("UPDATE edge_runs SET observation_count = observation_count + 1 WHERE run_id = ? AND edge_id = "
                     "(SELECT MIN(edge_id) FROM edge_runs WHERE run_id = ?)", (run_id, run_id))
    assert state(conn, run_id) == {"state": "incomplete", "expected": 2, "recorded": 2, "missing": 1, "unexpected": 0}
    with db.transaction(conn):                     # put the count back, then give this run a contribution its evidence does not support
        conn.execute("UPDATE edge_runs SET observation_count = observation_count - 1 WHERE run_id = ? AND edge_id = "
                     "(SELECT MIN(edge_id) FROM edge_runs WHERE run_id = ?)", (run_id, run_id))
    assert state(conn, run_id)["state"] == "recorded"
    other = relfx.fs_run(conn, [ok_record(r"C:pp\z.pem", 9)])
    with db.transaction(conn):
        conn.execute("INSERT INTO edge_runs SELECT edge_id, ?, observation_count, first_at, last_at FROM edge_runs WHERE run_id = ?", (run_id, other))
    assert state(conn, run_id) == {"state": "incomplete", "expected": 2, "recorded": 3, "missing": 0, "unexpected": 1}


# ------------------------------------------------------------------ process association (read time only)
def test_an_unambiguous_process_is_shown_and_never_stored_or_identified_by_pid(conn):
    run_id = relfx.tls_run(conn, [tls_record(1, port=8443), tls_record(1, port=8443)])
    item = read(conn, run_id)["items"][0]
    assert item["process"] == {"name": "svc.exe", "exe_path": "C:\\svc\\svc.exe"}
    assert "4321" not in repr(read(conn, run_id))                              # the PID never leaves
    assert conn.execute("SELECT COUNT(*) FROM nodes WHERE kind = 'process'").fetchone()[0] == 0
    assert "4321" not in repr([tuple(r) for r in conn.execute("SELECT * FROM nodes")] + [tuple(r) for r in conn.execute("SELECT * FROM edges")])


@pytest.mark.parametrize("second", [
    dict(process_name="other.exe", exe_path="C:\\other\\other.exe"),                                   # a different process
    dict(process_attribution="unavailable", pid=None, process_name=None, exe_path=None),               # one probe unattributed
    dict(process_attribution="not_found", pid=999, process_name=None, exe_path=None),
])
def test_an_ambiguous_process_is_not_shown(conn, second):
    run_id = relfx.tls_run(conn, [tls_record(1, port=8443), tls_record(1, port=8443, **second)])
    assert read(conn, run_id)["items"][0]["process"] is None


def test_an_unattributed_listener_has_no_process(conn):
    record = tls_record(1, port=8443, process_attribution="unavailable", pid=None, process_name=None, exe_path=None)
    run_id = relfx.tls_run(conn, [record])
    assert read(conn, run_id)["items"][0]["process"] is None


# ------------------------------------------------------------------ cross-source evidence
def test_a_presented_certificate_shows_separate_filesystem_evidence_without_implying_use(conn):
    fs_one = relfx.fs_run(conn, [ok_record(r"C:\certs\site.pem", 1)])
    fs_two = relfx.fs_run(conn, [ok_record(r"C:\certs\site.pem", 1), ok_record(r"C:\certs\copy.pem", 1)])
    other_host = relfx.fs_run(conn, [ok_record(r"D:\x\site.pem", 1)], host_id="host-b")
    tls = relfx.tls_run(conn, [tls_record(1, port=8443, peers=[peer(1, san=ok_record(n=1)["san"])]), tls_record(2, port=9443)])
    rows = {i["target"]["sha256"]: i for i in read(conn, tls)["items"]}
    found = rows[ingestfx.sha(1)]["filesystem_evidence"]
    assert found["omitted"] == 0
    by_host = {h["host_id"]: h for h in found["hosts"]}
    assert set(by_host) == {"agent-1", "host-b"}
    mine = by_host["agent-1"]
    assert (mine["runs"], mine["observations"], mine["hostname"]) == (2, 3, "WORKSTATION")
    assert mine["latest_run_id"] == fs_two and mine["latest_run_number"] == read(conn, fs_two)["run"]["run_number"]
    assert by_host["host-b"]["latest_run_id"] == other_host and fs_one != fs_two
    assert rows[ingestfx.sha(2)]["filesystem_evidence"] == {"hosts": [], "omitted": 0}      # nothing found on disk: stated, not invented
    # the TLS run itself recorded only its own kind of edge
    assert relfx.edge_kinds(conn) == {"stored_on", "presented_certificate"}
    assert all(i["kind"] == "presented_certificate" for i in read(conn, tls)["items"])


def test_filesystem_evidence_is_bounded(conn):
    for n in range(relationships.MAX_CROSS_HOSTS + 2):
        relfx.fs_run(conn, [ok_record(r"C:\certs\site.pem", 1)], host_id=f"host-{n}")
    tls = relfx.tls_run(conn, [tls_record(1, port=8443, peers=[peer(1, san=ok_record(n=1)["san"])])])
    evidence = read(conn, tls)["items"][0]["filesystem_evidence"]
    assert len(evidence["hosts"]) == relationships.MAX_CROSS_HOSTS and evidence["omitted"] == 2


# ------------------------------------------------------------------ bounds and order
def test_limit_total_truncation_and_a_stable_order(conn):
    records = [ok_record(rf"C:\app\f{n}.pem", n) for n in range(1, 8)]
    run_id = relfx.fs_run(conn, records)
    full = read(conn, run_id)
    assert full["total"] == 7 and full["truncated"] is False and len(full["items"]) == 7
    part = read(conn, run_id, limit=3)
    assert part["total"] == 7 and part["truncated"] is True and part["items"] == full["items"][:3] and part["limit"] == 3
    assert [i["source"]["label"] for i in full["items"]] == sorted(i["source"]["label"] for i in full["items"])
    assert read(conn, run_id) == full                                          # deterministic


@pytest.mark.parametrize("limit", [0, -1, relationships.MAX_LIMIT + 1, True, "5", 1.5])
def test_an_unacceptable_limit_is_refused(conn, limit):
    run_id = relfx.fs_run(conn, [ok_record()])
    from backend.reports import InvalidQuery
    with pytest.raises(InvalidQuery):
        read(conn, run_id, limit=limit)


def test_reading_writes_nothing(conn):
    run_id = relfx.tls_run(conn, tls_dataset())
    before = relfx.table_snapshot(conn)
    read(conn, run_id)
    read(conn, run_id, limit=1)
    assert relfx.table_snapshot(conn) == before


def test_nothing_secret_or_internal_is_published(conn):
    run_id = relfx.tls_run(conn, tls_dataset())
    text = repr(read(conn, run_id))
    for forbidden in ("BEGIN", "PRIVATE", "lease", "edge_id", "node_id", "pid", "communicates_with"):
        assert forbidden not in text, forbidden


# ------------------------------------------------------------------ defence in depth (not relying on ingestion's validation)
def test_only_completed_handshakes_count_even_if_the_database_held_an_inconsistent_row(conn):
    """Ingestion refuses certificates on a non-completed handshake, but relationships must not depend on that: plant such a row."""
    run_id = relfx.tls_run(conn, [tls_record(1, port=8443)])
    with db.transaction(conn):
        obs_id = conn.execute(
            "INSERT INTO tls_observations (run_id, seq, observed_at, direction, transport, src_ip, src_port, dst_ip, dst_port, "
            "handshake_outcome, cert_visibility, process_attribution, evidence_confidence) "
            "VALUES (?, 99, '2026-03-01T12:00:00Z', 'unknown', 'tcp', '127.0.0.1', 50099, '127.0.0.1', 9999, 'failed', 'not_observed', "
            "'unavailable', 'low')", (run_id,)).lastrowid
        conn.execute("INSERT INTO tls_peer_certificates (tls_observation_id, position, sha256) SELECT ?, 0, sha256 FROM certificates LIMIT 1", (obs_id,))
    assert state(conn, run_id)["state"] == "recorded"                      # the failed probe supports nothing
    with db.transaction(conn):
        assert relationships.record_run_in_tx(conn, run_id) == 0
    assert all("9999" not in key[2] for key in relfx.stored(conn, run_id))
