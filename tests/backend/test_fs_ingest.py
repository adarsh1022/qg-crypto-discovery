"""Ingestion semantics: identity vs sightings, duplicates, PKCS#12, replays, ordinals, rejection, atomicity, references."""
import datetime as dt
import sqlite3

import pytest

from backend import fs_ingest, fs_queries, runs
from backend import run_state as rs
from ingestfx import NOW, at, failure_record, ingest, ok_record, pfx_record, running_run, sha, STAMP


def rows(conn, sql, *params):
    return [dict(r) for r in conn.execute(sql, params)]


def observations(conn, run_id):
    return rows(conn, "SELECT seq, entry_ordinal, path, sha256, parse_status, chain_index, format FROM fs_observations "
                      "WHERE run_id = ? ORDER BY seq", run_id)


def count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


# ------------------------------------------------------------------ 1. create run + persist
def test_persist_observations_for_a_run(conn):
    run_id = running_run(conn)
    result = ingest(conn, run_id, [ok_record(n=1), failure_record(), ok_record(r"C:\app\b.pem", n=2)])
    assert result == fs_ingest.BatchResult(accepted=3, duplicates=0, rejected=())
    assert [(o["seq"], o["parse_status"]) for o in observations(conn, run_id)] == [(0, "ok"), (1, "access_denied"), (2, "ok")]
    assert count(conn, "certificates") == 2
    run = runs.get_run(conn, run_id)
    assert (run["record_count"], run["finding_count"], run["rejected_count"], run["error_count"]) == (3, 2, 0, 1)
    assert run["status"] == "running" and run["last_heartbeat_at"] == "2026-03-01T12:00:02.000Z"


def test_stored_observation_carries_the_records_facts(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\app\server.pem", n=5, key_size=3072, warnings=["serial_not_positive"],
                                    evidence_confidence="medium", extension_mismatch=True,
                                    not_before="2026-04-01T00:00:00Z", not_after="2026-02-26T12:00:00Z")])
    [obs] = fs_queries.list_fs_observations(conn, run_id)
    assert (obs["path"], obs["filename"], obs["format"], obs["parse_status"]) == (r"C:\app\server.pem", "server.pem", "pem", "ok")
    assert (obs["sha256"], obs["subject"], obs["issuer"], obs["key_algorithm"], obs["key_size"]) == (sha(5), "CN=cert5", "CN=Test CA", "RSA", 3072)
    assert (obs["warnings"], obs["evidence_confidence"], obs["extension_mismatch"], obs["not_yet_valid"]) == (
        ["serial_not_positive"], "medium", True, True)
    assert (obs["validity_status"], obs["days_to_expiry"], obs["discovered_at"]) == ("expired", -3, STAMP)
    assert obs["san"] == [{"type": "DNS", "value": "host5.example"}] and obs["is_ca"] is False


# ------------------------------------------------------------------ 2/3. identity vs observation
def test_same_certificate_at_two_paths_is_one_identity_and_two_observations(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\app\server.pem", n=1), ok_record(r"C:\backup\server.crt", n=1, format="der")])
    assert count(conn, "certificates") == 1
    assert [(o["path"], o["sha256"]) for o in observations(conn, run_id)] == [
        (r"C:\app\server.pem", sha(1)), (r"C:\backup\server.crt", sha(1))]
    counts = fs_queries.fs_counts(conn, run_id)
    assert (counts.sightings, counts.unique_certificates, counts.duplicate_observations, counts.repeats_within_file) == (2, 1, 1, 0)


def test_certificate_identity_is_reused_not_duplicated(conn):
    run_id = running_run(conn)
    for batch in range(3):
        ingest(conn, run_id, [ok_record(rf"C:\app\{batch}.pem", n=9)], start=batch)
    assert count(conn, "certificates") == 1 and count(conn, "fs_observations") == 3


def test_observation_identity_is_not_the_certificate_fingerprint(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)] * 4)                                   # one fingerprint, four sightings
    assert count(conn, "fs_observations") == 4
    assert len({o["seq"] for o in observations(conn, run_id)}) == 4


# ------------------------------------------------------------------ 4/7. PKCS#12
def test_duplicate_certificates_inside_one_pfx_remain_distinct_observations(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [pfx_record(n=1), pfx_record(n=2), pfx_record(n=2), pfx_record(n=3)])
    got = observations(conn, run_id)
    assert [o["sha256"] for o in got] == [sha(1), sha(2), sha(2), sha(3)]
    assert [o["entry_ordinal"] for o in got] == [0, 1, 2, 3]
    assert all(o["chain_index"] is None and o["format"] == "pkcs12" for o in got)       # 7. no chain position
    counts = fs_queries.fs_counts(conn, run_id)
    assert (counts.sightings, counts.unique_certificates, counts.duplicate_observations, counts.repeats_within_file) == (4, 3, 1, 1)
    assert count(conn, "certificates") == 3


def test_a_pfx_with_one_certificate_three_times_keeps_three_rows(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [pfx_record(n=4)] * 3)
    assert count(conn, "fs_observations") == 3 and count(conn, "certificates") == 1
    assert fs_queries.fs_counts(conn, run_id).repeats_within_file == 2


def test_pkcs12_chain_index_is_always_null_in_the_database(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [pfx_record(n=1), pfx_record(n=2)])
    assert conn.execute("SELECT COUNT(*) FROM fs_observations WHERE format = 'pkcs12' AND chain_index IS NOT NULL").fetchone()[0] == 0
    result = ingest(conn, run_id, [pfx_record(n=3, chain_index=1)], start=2)
    assert result.rejected == ((2, "pkcs12_chain_index"),) and count(conn, "fs_observations") == 2


def test_pem_chain_positions_are_kept(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1, chain_index=0, chain_total=2), ok_record(n=2, chain_index=1, chain_total=2)])
    assert [o["chain_index"] for o in observations(conn, run_id)] == [0, 1]


# ------------------------------------------------------------------ 8. integrity warning
def test_integrity_warning_and_reduced_confidence_are_preserved(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [pfx_record(n=1), pfx_record(n=2, warnings=["pkcs12_integrity_not_verified"], evidence_confidence="medium")])
    plain, decrypted = fs_queries.list_fs_observations(conn, run_id)
    assert plain["warnings"] == [] and plain["evidence_confidence"] == "high"
    assert decrypted["warnings"] == ["pkcs12_integrity_not_verified"] and decrypted["evidence_confidence"] == "medium"


def test_integrity_warning_with_high_confidence_is_refused(conn):
    run_id = running_run(conn)
    result = ingest(conn, run_id, [pfx_record(n=1, warnings=["pkcs12_integrity_not_verified"], evidence_confidence="high")])
    assert result.accepted == 0 and result.rejected == ((0, "integrity_warning_with_high_confidence"),)
    assert count(conn, "fs_observations") == 0 and count(conn, "certificates") == 0


# ------------------------------------------------------------------ 5. across runs
def test_same_certificate_across_two_runs(conn):
    first = running_run(conn)
    ingest(conn, first, [ok_record(r"C:\app\server.pem", n=1, discovered_at="2026-03-01T12:00:00Z")])
    second = running_run(conn)
    ingest(conn, second, [ok_record(r"C:\app\server.pem", n=1, discovered_at="2026-03-02T12:00:00Z")])
    assert count(conn, "certificates") == 1 and count(conn, "fs_observations") == 2
    cert = fs_queries.get_certificate(conn, sha(1))
    assert (cert["first_seen_run"], cert["first_seen_at"], cert["last_seen_run"], cert["last_seen_at"]) == (
        first, "2026-03-01T12:00:00Z", second, "2026-03-02T12:00:00Z")
    assert cert["sightings"] == 2 and [r["run_id"] for r in cert["runs"]] == [first, second]
    assert [fs_queries.fs_counts(conn, r).sightings for r in (first, second)] == [1, 1]


def test_seq_numbering_restarts_in_every_run(conn):
    first, second = running_run(conn), running_run(conn)
    ingest(conn, first, [ok_record(n=1)])
    ingest(conn, second, [ok_record(n=1)])                                       # seq 0 again: a different run, so fine
    assert count(conn, "fs_observations") == 2


def test_last_seen_does_not_move_backwards_when_an_older_run_is_ingested_late(conn):
    newer, older = running_run(conn), running_run(conn)
    ingest(conn, newer, [ok_record(n=1, discovered_at="2026-03-05T00:00:00Z")])
    ingest(conn, older, [ok_record(n=1, discovered_at="2026-03-01T00:00:00Z")])
    cert = fs_queries.get_certificate(conn, sha(1))
    assert (cert["first_seen_run"], cert["first_seen_at"]) == (older, "2026-03-01T00:00:00Z")
    assert (cert["last_seen_run"], cert["last_seen_at"]) == (newer, "2026-03-05T00:00:00Z")


# ------------------------------------------------------------------ 6. sequence / ordinal
def test_ordinal_counts_records_per_path_in_seq_order(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\a\x.pfx", n=1), ok_record(r"C:\a\y.pem", n=2), ok_record(r"C:\a\x.pfx", n=3),
                          failure_record(r"C:\a\z.pem"), ok_record(r"C:\a\x.pfx", n=4)])
    assert [(o["path"][-5:], o["entry_ordinal"]) for o in observations(conn, run_id)] == [
        ("x.pfx", 0), ("y.pem", 0), ("x.pfx", 1), ("z.pem", 0), ("x.pfx", 2)]


def test_ordinals_do_not_depend_on_arrival_order(conn):
    forward, backward = running_run(conn), running_run(conn)
    items = list(enumerate([pfx_record(n=1), pfx_record(n=2), pfx_record(n=2), pfx_record(n=3)]))
    fs_ingest.ingest_fs_batch(conn, forward, items, now=at(2))
    for pair in reversed(items):                                                 # one at a time, last first
        fs_ingest.ingest_fs_batch(conn, backward, [pair], now=at(2))
    assert observations(conn, forward) == observations(conn, backward)
    assert [o["entry_ordinal"] for o in observations(conn, backward)] == [0, 1, 2, 3]


def test_late_lower_seq_renumbers_existing_rows(conn):
    run_id = running_run(conn)
    fs_ingest.ingest_fs_batch(conn, run_id, [(5, pfx_record(n=2))], now=at(2))
    assert [o["entry_ordinal"] for o in observations(conn, run_id)] == [0]
    fs_ingest.ingest_fs_batch(conn, run_id, [(1, pfx_record(n=1))], now=at(3))
    assert [(o["seq"], o["entry_ordinal"]) for o in observations(conn, run_id)] == [(1, 0), (5, 1)]


def test_gaps_in_seq_are_allowed(conn):
    run_id = running_run(conn)
    fs_ingest.ingest_fs_batch(conn, run_id, [(10, ok_record(n=1)), (500, ok_record(n=2))], now=at(2))
    assert [o["seq"] for o in observations(conn, run_id)] == [10, 500]


def test_number_records_wraps_in_order(conn):
    assert fs_ingest.number_records(["a", "b"]) == [(0, "a"), (1, "b")]
    assert fs_ingest.number_records(["a"], start=7) == [(7, "a")]


# ------------------------------------------------------------------ 19. repeated ingestion
def test_replaying_a_batch_changes_nothing(conn):
    run_id = running_run(conn)
    batch = [pfx_record(n=1), pfx_record(n=1), ok_record(r"C:\b\a.pem", n=2), failure_record()]
    first = ingest(conn, run_id, batch)
    before = (observations(conn, run_id), rows(conn, "SELECT * FROM certificates"), rows(conn, "SELECT * FROM run_issues"))
    again = ingest(conn, run_id, batch)
    assert first.accepted == 4 and again == fs_ingest.BatchResult(accepted=0, duplicates=4, rejected=())
    assert (observations(conn, run_id), rows(conn, "SELECT * FROM certificates"), rows(conn, "SELECT * FROM run_issues")) == before


def test_replay_keeps_legitimate_duplicates_apart_from_replays(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [pfx_record(n=1), pfx_record(n=1)])                     # two genuine sightings (seq 0 and 1)
    ingest(conn, run_id, [pfx_record(n=1), pfx_record(n=1)])                     # the same batch again
    assert count(conn, "fs_observations") == 2
    ingest(conn, run_id, [pfx_record(n=1)], start=2)                             # a genuine third sighting: new seq
    assert count(conn, "fs_observations") == 3


def test_partial_replay_adds_only_the_new_records(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), ok_record(n=2)])
    result = ingest(conn, run_id, [ok_record(n=1), ok_record(n=2), ok_record(n=3)])
    assert (result.accepted, result.duplicates) == (1, 2) and count(conn, "fs_observations") == 3


def test_same_seq_with_different_content_is_a_conflict_and_the_first_write_stands(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\a\one.pem", n=1)])
    result = ingest(conn, run_id, [ok_record(r"C:\a\two.pem", n=2)])             # seq 0 again, different record
    assert result == fs_ingest.BatchResult(accepted=0, duplicates=0, rejected=(), conflicts=(0,))
    assert [o["path"] for o in observations(conn, run_id)] == [r"C:\a\one.pem"]
    assert ingest(conn, run_id, [ok_record(r"C:\a\two.pem", n=2)]) == fs_ingest.BatchResult(0, 1, ())   # replay: no second issue
    assert count(conn, "run_issues") == 1 and runs.get_run(conn, run_id)["rejected_count"] == 0


def test_a_rejected_seq_stays_rejected_even_if_resent_valid(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1, key_size=0)])                           # rejected
    result = ingest(conn, run_id, [ok_record(n=1)])                              # same seq, now valid
    assert (result.accepted, result.duplicates) == (0, 1) and count(conn, "fs_observations") == 0
    assert count(conn, "run_issues") == 1


def test_identical_record_twice_in_one_batch_with_the_same_seq(conn):
    run_id = running_run(conn)
    result = fs_ingest.ingest_fs_batch(conn, run_id, [(0, ok_record(n=1)), (0, ok_record(n=1))], now=at(2))
    assert (result.accepted, result.duplicates) == (1, 1)


# ------------------------------------------------------------------ rejection handling
def test_bad_records_are_rejected_without_stopping_the_batch(conn):
    run_id = running_run(conn)
    bad_path = ok_record(n=3)
    bad_path["der"] = "3082"
    result = ingest(conn, run_id, [ok_record(n=1), ok_record(n=2, sha256="nope"), bad_path, "not a dict", ok_record(n=4)])
    assert result.accepted == 2
    assert result.rejected == ((1, "bad_sha256"), (2, "unknown_field"), (3, "not_an_object"))
    issues = fs_queries.list_run_issues(conn, run_id)
    assert [(i["source"], i["kind"], i["code"], i["seq"]) for i in issues] == [
        ("backend", "rejected_record", "bad_sha256", 1), ("backend", "rejected_record", "unknown_field", 2),
        ("backend", "rejected_record", "not_an_object", 3)]
    assert runs.get_run(conn, run_id)["rejected_count"] == 3


def test_rejection_issue_repeats_the_path_only_when_it_is_clean(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\clean\a.pem", n=1, key_size=0),
                          ok_record("C:\\armor\\-----BEGIN CERTIFICATE-----", n=2),
                          ok_record("C:\\sur\\\ud800.pem", n=3, key_size=0), {"path": 5}])
    paths = [i["path"] for i in fs_queries.list_run_issues(conn, run_id)]
    assert paths == [r"C:\clean\a.pem", None, "C:\\sur\\\\ud800.pem", None]


def test_rejected_records_leave_no_certificate_behind(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1, discovered_at="garbage")])
    assert count(conn, "certificates") == 0 and count(conn, "fs_observations") == 0


def test_certificate_identity_conflict_is_refused_and_never_overwrites(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\a\real.pem", n=1)])
    forged = ok_record(r"C:\a\forged.pem", n=1, subject="CN=Somebody Else", key_size=1024)       # same fingerprint, other facts
    result = ingest(conn, run_id, [forged], start=1)
    assert result.rejected == ((1, "certificate_identity_conflict"),)
    cert = fs_queries.get_certificate(conn, sha(1))
    assert (cert["subject"], cert["key_size"]) == ("CN=cert1", 2048) and count(conn, "fs_observations") == 1


def test_matching_facts_for_a_known_fingerprint_are_accepted(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\a\1.pem", n=1), ok_record(r"C:\b\2.pem", n=1, chain_index=1, chain_total=3,
                                                                  chain_role="ca", evidence_confidence="medium",
                                                                  warnings=["serial_not_positive"])])
    assert count(conn, "fs_observations") == 2 and count(conn, "certificates") == 1      # per-sighting fields may differ


@pytest.mark.parametrize("batch", [5, "records", [1, 2], [(0,)], [(0, {}, 1)], [("0", {})], [(-1, {})], [(True, {})],
                                   [(2**31, {})], [(1.5, {})], [None]])
def test_malformed_batches_are_refused_before_anything_is_stored(conn, batch):
    run_id = running_run(conn)
    with pytest.raises(fs_ingest.BatchRejected):
        fs_ingest.ingest_fs_batch(conn, run_id, batch, now=at(2))
    assert count(conn, "fs_observations") == 0 and not conn.in_transaction


def test_an_empty_batch_is_a_valid_noop_that_still_counts_as_a_heartbeat(conn):
    run_id = running_run(conn)
    assert fs_ingest.ingest_fs_batch(conn, run_id, [], now=at(30)) == fs_ingest.BatchResult(0, 0, ())
    assert runs.get_run(conn, run_id)["last_heartbeat_at"] == "2026-03-01T12:00:30.000Z"


# ------------------------------------------------------------------ 9. access / read issues as stored evidence
def test_access_and_read_errors_are_stored_as_observations_with_no_certificate(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [failure_record(r"C:\a\locked.pem", "access_denied"),
                          failure_record(r"C:\a\gone.pem", "read_error", detail="internal_error", access_error=None)])
    got = fs_queries.list_fs_observations(conn, run_id)
    assert [(o["parse_status"], o["sha256"], o["evidence_confidence"]) for o in got] == [
        ("access_denied", None, "low"), ("read_error", None, "low")]
    assert got[0]["access_error"] == "PermissionError:WinError 5" and got[0]["detail"] == "read_failed"
    assert runs.get_run(conn, run_id)["error_count"] == 2
    assert count(conn, "certificates") == 0


# ------------------------------------------------------------------ 14. transactions
def test_unexpected_failure_rolls_the_whole_batch_back(conn, monkeypatch):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\kept\a.pem", n=1)])
    real = fs_ingest._certificate_upserted
    calls = []

    def flaky(c, r, valid):
        calls.append(1)
        if len(calls) == 3:
            raise RuntimeError("disk exploded")
        return real(c, r, valid)
    monkeypatch.setattr(fs_ingest, "_certificate_upserted", flaky)
    with pytest.raises(RuntimeError):
        ingest(conn, run_id, [ok_record(n=10), ok_record(n=11), ok_record(n=12), ok_record(n=13)], start=1)
    assert not conn.in_transaction
    assert [o["path"] for o in observations(conn, run_id)] == [r"C:\kept\a.pem"]
    assert count(conn, "certificates") == 1                                      # the certificates of the failed batch are gone too
    assert runs.get_run(conn, run_id)["record_count"] == 1                       # counters untouched


def test_failure_after_inserts_rolls_back_ordinals_issues_and_counters(conn, monkeypatch):
    run_id = running_run(conn)
    monkeypatch.setattr(fs_ingest, "_renumber_ordinals", lambda *a: (_ for _ in ()).throw(RuntimeError("late failure")))
    with pytest.raises(RuntimeError):
        ingest(conn, run_id, [ok_record(n=1), ok_record(n=2, key_size=0)])
    assert count(conn, "fs_observations") == 0 and count(conn, "certificates") == 0 and count(conn, "run_issues") == 0
    assert runs.get_run(conn, run_id)["record_count"] == 0 and not conn.in_transaction


def test_database_constraint_failure_rolls_back_and_propagates(conn, monkeypatch):
    run_id = running_run(conn)
    real_validate = fs_ingest.validate_fs_record

    def lying_validator(record, **kwargs):
        valid = real_validate(record, **kwargs)
        if valid.observation["path"].endswith("poison.pem"):
            valid.observation["evidence_confidence"] = "certain"                 # would violate the CHECK constraint
        return valid
    monkeypatch.setattr(fs_ingest, "validate_fs_record", lying_validator)
    with pytest.raises(sqlite3.IntegrityError):
        ingest(conn, run_id, [ok_record(r"C:\a\fine.pem", n=1), ok_record(r"C:\a\poison.pem", n=2)])
    assert count(conn, "fs_observations") == 0 and count(conn, "certificates") == 0


def test_the_connection_is_usable_after_a_rolled_back_batch(conn, monkeypatch):
    run_id = running_run(conn)
    monkeypatch.setattr(fs_ingest, "_renumber_ordinals", lambda *a: (_ for _ in ()).throw(RuntimeError("x")))
    with pytest.raises(RuntimeError):
        ingest(conn, run_id, [ok_record(n=1)])
    monkeypatch.undo()
    assert ingest(conn, run_id, [ok_record(n=1)]).accepted == 1


# ------------------------------------------------------------------ 17/18. references
def test_unknown_run_is_refused(conn):
    with pytest.raises(runs.RunNotFound):
        ingest(conn, "no-such-run", [ok_record(n=1)])
    assert count(conn, "fs_observations") == 0 and count(conn, "certificates") == 0 and not conn.in_transaction


def test_records_are_refused_for_runs_that_are_not_running(conn):
    queued = runs.create_run(conn, "filesystem", "manual", now=NOW)
    with pytest.raises(fs_ingest.RunNotWritable, match="queued"):
        ingest(conn, queued, [ok_record(n=1)])
    done = running_run(conn)
    runs.fail_run(conn, done, now=at(5), code="x")
    with pytest.raises(fs_ingest.RunNotWritable, match="failed"):
        ingest(conn, done, [ok_record(n=1)])
    assert issubclass(fs_ingest.RunNotWritable, rs.InvalidTransition)
    assert count(conn, "fs_observations") == 0 and count(conn, "certificates") == 0


def test_records_are_refused_for_a_run_of_another_type(conn):
    tls = running_run(conn, run_type="tls")
    with pytest.raises(runs.WrongRunType):
        ingest(conn, tls, [ok_record(n=1)])
    assert count(conn, "fs_observations") == 0


def test_foreign_key_integrity_holds_after_every_kind_of_ingestion(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), pfx_record(n=2), pfx_record(n=2), failure_record(), ok_record(n=3, key_size=0)])
    ingest(conn, run_id, [ok_record(n=1)])
    other = running_run(conn)
    ingest(conn, other, [ok_record(n=1), ok_record(n=5)])
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_observations_cannot_point_at_unknown_certificates_or_runs(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM certificates WHERE sha256 = ?", (sha(1),))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE fs_observations SET sha256 = ? WHERE run_id = ?", (sha(99), run_id))


# ------------------------------------------------------------------ 20. unicode
def test_unicode_and_surrogate_metadata_is_stored_safely(conn):
    run_id = running_run(conn)
    odd = "C:\\证书\\ключ-😀\\bad\ud800name.pem"
    ingest(conn, run_id, [ok_record(odd, n=1, subject="CN=Zoë 😀 \ud83d", issuer="CN=Ünïcode\x00CA"),
                          ok_record("C:\\证书\\ключ-😀\\plain.pem", n=2)])
    [first, second] = fs_queries.list_fs_observations(conn, run_id)
    assert first["path"] == "C:\\证书\\ключ-😀\\bad\\ud800name.pem"
    assert first["subject"] == "CN=Zoë 😀 \\ud83d" and first["issuer"] == "CN=Ünïcode\\x00CA"
    assert second["path"] == "C:\\证书\\ключ-😀\\plain.pem"
    for value in first.values():
        if isinstance(value, str):
            value.encode("utf-8")                                                # strict UTF-8 round trip


def test_sanitised_paths_are_matched_consistently_for_ordinals_and_replays(conn):
    run_id = running_run(conn)
    path = "C:\\x\\bad\ud800.pfx"
    ingest(conn, run_id, [pfx_record(path, n=1), pfx_record(path, n=2)])
    assert [o["entry_ordinal"] for o in observations(conn, run_id)] == [0, 1]
    assert ingest(conn, run_id, [pfx_record(path, n=1), pfx_record(path, n=2)]).duplicates == 2


# ------------------------------------------------------------------ queries
def test_list_fs_observations_filters_and_pages(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\a\1.pem", n=1), ok_record(r"C:\a\2.pem", n=2, not_after="2026-02-28T00:00:00Z"),
                          failure_record(), ok_record(r"C:\a\1.pem", n=1)])
    assert [o["seq"] for o in fs_queries.list_fs_observations(conn, run_id)] == [0, 1, 2, 3]
    assert [o["seq"] for o in fs_queries.list_fs_observations(conn, run_id, parse_status="ok")] == [0, 1, 3]
    assert [o["seq"] for o in fs_queries.list_fs_observations(conn, run_id, validity_status="expired")] == [1]
    assert [o["seq"] for o in fs_queries.list_fs_observations(conn, run_id, sha256=sha(1))] == [0, 3]
    assert [o["seq"] for o in fs_queries.list_fs_observations(conn, run_id, path=r"C:\a\1.pem")] == [0, 3]
    assert [o["seq"] for o in fs_queries.list_fs_observations(conn, run_id, limit=2, offset=1)] == [1, 2]
    assert fs_queries.list_fs_observations(conn, "other-run") == []
    for bad in (dict(parse_status="weird"), dict(validity_status="fine"), dict(limit=-1)):
        with pytest.raises(ValueError):
            fs_queries.list_fs_observations(conn, run_id, **bad)
    assert fs_queries.list_fs_observations(conn, run_id, path="x' OR '1'='1") == []


def test_observation_listing_is_scoped_to_its_run(conn):
    a, b = running_run(conn), running_run(conn)
    ingest(conn, a, [ok_record(n=1)])
    ingest(conn, b, [ok_record(n=2), ok_record(n=3)])
    assert len(fs_queries.list_fs_observations(conn, a)) == 1 and len(fs_queries.list_fs_observations(conn, b)) == 2


def test_fs_counts_separates_sightings_from_unique_certificates(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\a\1.pem", n=1), ok_record(r"C:\b\1.pem", n=1), pfx_record(n=2), pfx_record(n=2),
                          ok_record(r"C:\a\3.pem", n=3, not_after="2026-03-10T00:00:00Z"), failure_record(),
                          failure_record(r"C:\a\bad.pem", "access_denied")])
    counts = fs_queries.fs_counts(conn, run_id)
    assert counts.observations == 7 and counts.sightings == 5 and counts.unique_certificates == 3
    assert counts.duplicate_observations == 2 and counts.repeats_within_file == 1
    assert counts.by_parse_status == {"ok": 5, "access_denied": 2}
    assert counts.by_validity_status == {"valid": 4, "expiring": 1}
    assert counts.parse_failures == 2 and counts.rejected == 0


def test_get_certificate_unknown_returns_none(conn):
    assert fs_queries.get_certificate(conn, sha(1)) is None


def test_batch_time_is_recorded_as_the_runs_heartbeat(conn):
    run_id = running_run(conn)
    later = dt.datetime(2026, 3, 1, 12, 5, tzinfo=dt.timezone.utc)
    fs_ingest.ingest_fs_batch(conn, run_id, [(0, ok_record(n=1))], now=later)
    assert runs.get_run(conn, run_id)["last_heartbeat_at"] == "2026-03-01T12:05:00.000Z"
