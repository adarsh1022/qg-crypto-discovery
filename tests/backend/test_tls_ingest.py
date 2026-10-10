"""TLS ingestion: what is stored for a probe record, how replays/conflicts/rejections behave, and what the counts mean."""
import json

import pytest

from backend import db, fs_ingest, runs, tls_ingest
from backend import run_state as rs
from tlsingestfx import (MARKERS, NOW, at, deep, failed_record, ingest, peer, running_tls_run, sha, tls_record)
from ingestfx import ok_record, running_run


def rows(conn, sql, *args):
    return [dict(r) for r in conn.execute(sql, args)]


def observations(conn, run_id):
    return rows(conn, "SELECT * FROM tls_observations WHERE run_id = ? ORDER BY seq", run_id)


def issues(conn, run_id):
    return rows(conn, "SELECT source, kind, code, seq, path FROM run_issues WHERE run_id = ? ORDER BY id", run_id)


@pytest.fixture
def run(conn):
    return running_tls_run(conn)


# ------------------------------------------------------------------ what is stored
def test_a_probe_record_is_stored_exactly_as_an_active_probe_of_a_listener(conn, run):
    result = ingest(conn, run, [tls_record(1, port=8443)])
    assert (result.accepted, result.duplicates, result.rejected, result.conflicts) == (1, 0, (), ())
    (row,) = observations(conn, run)
    assert (row["direction"], row["transport"], row["sni"]) == ("unknown", "tcp", None)
    assert (row["local_ip"], row["local_port"], row["remote_ip"], row["remote_port"], row["last_event_at"], row["cipher_id"]) == (None,) * 6
    assert (row["src_ip"], row["src_port"], row["dst_ip"], row["dst_port"]) == ("127.0.0.1", 50001, "127.0.0.1", 8443)
    assert (row["handshake_outcome"], row["tls_version"], row["cipher_suite"], row["cert_visibility"]) == ("completed", "TLS1.3", "TLS_AES_256_GCM_SHA384", "visible")
    assert (row["pid"], row["process_name"], row["exe_path"], row["process_attribution"]) == (4321, "svc.exe", "C:\\svc\\svc.exe", "attributed")
    assert (row["event_count"], row["packet_count"]) == (1, 0)
    assert json.loads(row["event_counts_json"]) == {"handshake_completed": 1, "probe_attempts": 1}
    assert json.loads(row["warnings_json"]) == MARKERS and row["evidence_confidence"] == "high"


def test_the_peer_certificate_enters_the_catalog_and_is_linked_leaf_first(conn, run):
    ingest(conn, run, [tls_record(1, peers=[peer(1), peer(2, is_ca=True), peer(3, is_ca=True)])])
    assert [r["sha256"] for r in rows(conn, "SELECT sha256 FROM tls_peer_certificates ORDER BY position")] == [sha(1), sha(2), sha(3)]
    cert = rows(conn, "SELECT * FROM certificates WHERE sha256 = ?", sha(1))[0]
    assert (cert["subject"], cert["issuer"], cert["key_algorithm"], cert["key_size"], cert["is_ca"]) == ("CN=cert1", "CN=Test CA", "RSA", 2048, 0)
    assert json.loads(cert["san_json"]) == [{"type": "dns", "value": "host1.example"}]
    assert (cert["first_seen_run"], cert["last_seen_run"], cert["first_seen_at"]) == (run, run, "2026-03-01T12:00:00Z")


def test_the_same_fingerprint_at_two_chain_positions_is_one_catalog_row_and_two_links(conn, run):
    ingest(conn, run, [tls_record(1, peers=[peer(1), peer(2, is_ca=True), peer(1)])])
    assert [r["sha256"] for r in rows(conn, "SELECT sha256 FROM tls_peer_certificates ORDER BY position")] == [sha(1), sha(2), sha(1)]
    assert rows(conn, "SELECT COUNT(*) AS n FROM certificates")[0]["n"] == 2


def test_probing_the_same_service_twice_gives_two_observations_but_one_certificate(conn, run):
    ingest(conn, run, [tls_record(1, src_port=50001), tls_record(1, src_port=50002)])
    assert len(observations(conn, run)) == 2
    assert rows(conn, "SELECT COUNT(*) AS n FROM certificates")[0]["n"] == 1
    assert rows(conn, "SELECT COUNT(*) AS n FROM tls_peer_certificates")[0]["n"] == 2


def test_a_certificate_seen_in_a_filesystem_run_and_a_probe_is_one_catalog_row(conn):
    fs_run = running_run(conn)
    fs_ingest.ingest_fs_batch(conn, fs_run, fs_ingest.number_records([ok_record(n=1)]), now=at(2))
    tls_run = running_tls_run(conn)
    # the filesystem fixture's certificate facts are the same as peer(1)'s, so it is the same certificate
    fs_facts = rows(conn, "SELECT * FROM certificates WHERE sha256 = ?", sha(1))[0]
    ingest(conn, tls_run, [tls_record(1, peers=[peer(1, subject=fs_facts["subject"], issuer=fs_facts["issuer"], serial_hex=fs_facts["serial_hex"],
                                                       san=[{"type": "DNS", "value": "host1.example"}], not_before=fs_facts["not_before"],
                                                       not_after=fs_facts["not_after"], is_ca=False)])])
    cert = rows(conn, "SELECT * FROM certificates WHERE sha256 = ?", sha(1))
    assert len(cert) == 1 and cert[0]["first_seen_run"] == fs_run and cert[0]["last_seen_run"] == tls_run


def test_certificate_catalog_is_shared_across_tls_runs(conn):
    first, second = running_tls_run(conn), running_tls_run(conn)
    ingest(conn, first, [tls_record(1)])
    ingest(conn, second, [tls_record(1)], now=at(5))
    cert = rows(conn, "SELECT * FROM certificates WHERE sha256 = ?", sha(1))
    assert len(cert) == 1 and cert[0]["first_seen_run"] == first


def test_inconclusive_probes_are_stored_as_evidence_without_version_cipher_or_certificate(conn, run):
    ingest(conn, run, [failed_record(9000), failed_record(9001, outcome="incomplete", code="connect_timeout"),
                       failed_record(9002, outcome="alert", code="tlsv1_alert_protocol_version")])
    stored = observations(conn, run)
    assert [r["handshake_outcome"] for r in stored] == ["failed", "incomplete", "alert"]
    assert all(r["tls_version"] is None and r["cipher_suite"] is None and r["cert_visibility"] == "not_observed" for r in stored)
    assert rows(conn, "SELECT COUNT(*) AS n FROM tls_peer_certificates")[0]["n"] == 0
    assert rows(conn, "SELECT COUNT(*) AS n FROM certificates")[0]["n"] == 0


# ------------------------------------------------------------------ counts come from stored rows
def test_only_completed_handshakes_are_findings(conn, run):
    ingest(conn, run, [tls_record(1), failed_record(9000), failed_record(9001, outcome="incomplete", code="connect_timeout"),
                       failed_record(9002, outcome="alert", code="x_alert"), failed_record(9003, outcome="unknown", code="unrecognised_handshake_details"),
                       tls_record(2, port=8444)])
    state = runs.load_state(conn, run)
    assert (state.record_count, state.finding_count, state.rejected_count, state.error_count) == (6, 2, 0, 0)
    assert tls_ingest.derived_counts(conn, run) == rs.Counts(records=6, findings=2, rejected=0, errors=0)


def test_counts_follow_each_batch_and_heartbeat(conn, run):
    ingest(conn, run, [tls_record(1)])
    assert runs.load_state(conn, run).record_count == 1
    ingest(conn, run, [failed_record(9000)], start=1, now=at(7))
    state = runs.load_state(conn, run)
    assert (state.record_count, state.finding_count, state.last_heartbeat_at) == (2, 1, rs.format_ts(at(7)))


# ------------------------------------------------------------------ replays, conflicts, rejections
def test_an_exact_replay_changes_nothing(conn, run):
    ingest(conn, run, [tls_record(1, peers=[peer(1), peer(2, is_ca=True)])])
    before = observations(conn, run)
    again = ingest(conn, run, [tls_record(1, peers=[peer(1), peer(2, is_ca=True)])], now=at(5))
    assert (again.accepted, again.duplicates, again.rejected, again.conflicts) == (0, 1, (), ())
    assert observations(conn, run) == before and issues(conn, run) == []
    assert rows(conn, "SELECT COUNT(*) AS n FROM tls_peer_certificates")[0]["n"] == 2


def test_a_stored_seq_with_different_content_is_a_conflict_and_the_stored_row_is_untouched(conn, run):
    ingest(conn, run, [tls_record(1)])
    before = observations(conn, run)
    result = ingest(conn, run, [tls_record(1, tls_version="TLS1.2")], now=at(5))
    assert (result.accepted, result.duplicates, result.conflicts) == (0, 0, (0,))
    assert observations(conn, run) == before
    assert issues(conn, run) == [dict(source="backend", kind="seq_conflict", code="seq_conflict", seq=0, path=None)]
    again = ingest(conn, run, [tls_record(1, tls_version="TLS1.2")], now=at(6))
    assert again.conflicts == () and again.duplicates == 1 and len(issues(conn, run)) == 1       # one issue per seq


def test_a_different_chain_for_a_stored_seq_is_a_conflict(conn, run):
    ingest(conn, run, [tls_record(1, peers=[peer(1)])])
    assert ingest(conn, run, [tls_record(1, peers=[peer(1), peer(2, is_ca=True)])], now=at(5)).conflicts == (0,)


def test_an_invalid_record_for_a_stored_seq_is_a_conflict_not_a_rejection(conn, run):
    ingest(conn, run, [tls_record(1)])
    bad = tls_record(1)
    bad["direction"] = "inbound"
    result = ingest(conn, run, [bad], now=at(5))
    assert result.conflicts == (0,) and result.rejected == ()
    assert [i["kind"] for i in issues(conn, run)] == ["seq_conflict"]


def test_a_bad_record_never_stops_the_batch_and_is_rejected_once(conn, run):
    bad = tls_record(2)
    bad["packet_count"] = 40
    result = ingest(conn, run, [tls_record(1), bad, tls_record(3, port=8445)])
    assert result.accepted == 2 and result.rejected == ((1, "bad_packet_count"),)
    assert [r["seq"] for r in observations(conn, run)] == [0, 2]
    assert issues(conn, run) == [dict(source="backend", kind="rejected_record", code="bad_packet_count", seq=1, path=None)]
    again = ingest(conn, run, [tls_record(1), bad, tls_record(3, port=8445)], now=at(5))
    assert (again.accepted, again.duplicates, again.rejected) == (0, 3, ())
    assert len(issues(conn, run)) == 1
    assert runs.load_state(conn, run).rejected_count == 1


def test_a_rejected_seq_stays_rejected_even_if_a_valid_record_is_sent_for_it(conn, run):
    bad = tls_record(1)
    del bad["warnings"]
    ingest(conn, run, [bad])
    result = ingest(conn, run, [tls_record(1)], now=at(5))
    assert (result.accepted, result.duplicates) == (0, 1) and observations(conn, run) == []


def test_records_missing_the_probe_markers_are_rejected_and_not_stored(conn, run):
    result = ingest(conn, run, [tls_record(1, warnings=[], evidence_confidence="high")])
    assert result.rejected == ((0, "missing_probe_markers"),) and observations(conn, run) == []


def test_fixed_codes_only_in_issues_never_record_content(conn, run):
    record = tls_record(1)
    record["process_name"] = "secret-process-name -----BEGIN PRIVATE KEY-----"
    ingest(conn, run, [record])
    text = json.dumps(issues(conn, run))
    assert "secret" not in text and "BEGIN" not in text and "pem_armor_in_process_name" in text


def test_a_certificate_with_known_fingerprint_but_different_facts_is_rejected_before_anything_is_written(conn, run):
    ingest(conn, run, [tls_record(2, peers=[peer(2)])])
    catalog = rows(conn, "SELECT * FROM certificates ORDER BY sha256")
    result = ingest(conn, run, [tls_record(1, peers=[peer(1), peer(2, subject="CN=someone-else")])], start=1, now=at(5))
    assert result.rejected == ((1, "certificate_identity_conflict"),)
    assert [r["seq"] for r in observations(conn, run)] == [0]                            # no observation for it
    assert rows(conn, "SELECT * FROM certificates ORDER BY sha256") == catalog           # and peer(1) did NOT enter the catalog
    assert rows(conn, "SELECT COUNT(*) AS n FROM tls_peer_certificates")[0]["n"] == 1


def test_one_fingerprint_with_two_different_fact_sets_in_one_record_is_refused(conn, run):
    result = ingest(conn, run, [tls_record(1, peers=[peer(1), peer(1, subject="CN=other")])])
    assert result.rejected == ((0, "certificate_identity_conflict"),) and observations(conn, run) == []


# ------------------------------------------------------------------ the batch envelope
@pytest.mark.parametrize("items", [[1], [(1,)], [(1, 2, 3)], [("0", {})], [(-1, {})], [(True, {})], [(2**31, {})], 5])
def test_a_malformed_envelope_refuses_the_whole_batch_and_stores_nothing(conn, run, items):
    with pytest.raises(fs_ingest.BatchRejected):
        with db.transaction(conn):
            tls_ingest.ingest_tls_batch_in_tx(conn, run, items, now=at(2))
    assert observations(conn, run) == []


def test_items_may_be_lists_as_json_produces_them(conn, run):
    with db.transaction(conn):
        result = tls_ingest.ingest_tls_batch_in_tx(conn, run, [[0, tls_record(1)]], now=at(2))
    assert result.accepted == 1


def test_an_unexpected_error_rolls_the_whole_batch_back(conn, run, monkeypatch):
    calls = []
    original = tls_ingest._ingest_one

    def flaky(conn, run_id, seq, record):
        calls.append(seq)
        if seq == 1:
            raise RuntimeError("boom")
        return original(conn, run_id, seq, record)

    monkeypatch.setattr(tls_ingest, "_ingest_one", flaky)
    with pytest.raises(RuntimeError):
        ingest(conn, run, [tls_record(1), tls_record(2, port=8444)])
    assert observations(conn, run) == [] and rows(conn, "SELECT COUNT(*) AS n FROM certificates")[0]["n"] == 0


# ------------------------------------------------------------------ isolation and run types
def test_runs_are_isolated(conn):
    a, b = running_tls_run(conn), running_tls_run(conn)
    ingest(conn, a, [tls_record(1), tls_record(2, port=8444)])
    ingest(conn, b, [tls_record(1)])
    assert [r["seq"] for r in observations(conn, a)] == [0, 1] and [r["seq"] for r in observations(conn, b)] == [0]
    assert runs.load_state(conn, a).record_count == 2 and runs.load_state(conn, b).record_count == 1
    assert issues(conn, a) == [] and issues(conn, b) == []


def test_only_a_running_tls_run_accepts_records(conn):
    queued = runs.create_run(conn, "tls", "manual", now=NOW)
    with pytest.raises(rs.InvalidTransition):
        ingest(conn, queued, [tls_record(1)])
    done = running_tls_run(conn)
    ingest(conn, done, [tls_record(1)])
    with db.transaction(conn):
        tls_ingest.finalize_tls_run_in_tx(conn, done, now=at(9), summary=None)
    with pytest.raises(rs.InvalidTransition):
        ingest(conn, done, [tls_record(2, port=8444)], now=at(11))


def test_the_two_run_types_cannot_write_to_each_other(conn):
    fs_run, tls_run = running_run(conn), running_tls_run(conn)
    with pytest.raises(runs.WrongRunType):
        ingest(conn, fs_run, [tls_record(1)])
    with pytest.raises(runs.WrongRunType):
        fs_ingest.ingest_fs_batch(conn, tls_run, fs_ingest.number_records([ok_record(n=1)]), now=at(2))
    with pytest.raises(runs.RunNotFound):
        ingest(conn, "f" * 32, [tls_record(1)])


def test_a_filesystem_record_is_rejected_by_the_tls_validator_and_a_tls_record_by_the_filesystem_one(conn):
    fs_run, tls_run = running_run(conn), running_tls_run(conn)
    assert ingest(conn, tls_run, [ok_record(n=1)]).rejected == ((0, "unknown_field"),)
    result = fs_ingest.ingest_fs_batch(conn, fs_run, fs_ingest.number_records([tls_record(1)]), now=at(2))
    assert result.rejected and result.accepted == 0


# ------------------------------------------------------------------ nothing sensitive is stored
def test_no_certificate_bytes_or_armour_reach_the_database(conn, run):
    record = tls_record(1)
    record["pem"] = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    record["der"] = "MIIBxyz"
    assert ingest(conn, run, [record]).rejected == ((0, "unknown_field"),)
    ingest(conn, run, [tls_record(2, port=8444)], start=1, now=at(5))
    dump = json.dumps({t: rows(conn, f"SELECT * FROM {t}") for t in ("tls_observations", "tls_peer_certificates", "certificates", "run_issues")})
    assert "BEGIN" not in dump and "MIIB" not in dump
    _ = deep
