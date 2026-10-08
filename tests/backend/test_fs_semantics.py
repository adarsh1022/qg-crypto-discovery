"""S2 derived-claim consistency, S4 conflicting replays, S5 read-error reconciliation, and the pinned S6 policy.

S2  validity_status / days_to_expiry / not_yet_valid must follow from the dates; confidence must follow from the warnings.
S4  a seq re-sent with contradicting content is a conflict (partial run), not an ordinary rejected record.
S5  a read error the agent reported must affect the run's status even when no matching observation was stored.
S6  scan-policy boundaries (depth, size, exclusions, links, placeholders, overlap) stay non-failures.
"""
import datetime as dt
import random

import pytest

import pemgen
import pfxgen
from agent import scan_config, x509_parse
from agent.x509_parse import assess_validity
from backend import fs_ingest, fs_queries, fs_record, run_state as rs, runs
from backend.fs_record import RecordRejected, validate_fs_record
from ingestfx import (NOW, STAMP, at, dir_error, failure_record, finish, ingest, ok_record, pfx_record, running_run,
                      sha, summary)
from treegen import put, run_scan

UTC = dt.timezone.utc
DISCOVERED = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)               # == STAMP in ingestfx


def stamp(moment: dt.datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def rejection(record, **kwargs) -> str:
    with pytest.raises(RecordRejected) as info:
        validate_fs_record(record, **kwargs)
    return info.value.code


def claiming(status, days, not_yet_valid=False, *, not_after, not_before="2025-01-01T00:00:00Z", **extra):
    """An ok record whose validity claims are set explicitly (so tests can state contradictions)."""
    return ok_record(n=1, not_before=not_before, not_after=not_after, validity_status=status, days_to_expiry=days,
                     not_yet_valid=not_yet_valid, **extra)


def after_discovery(**delta) -> str:
    return stamp(DISCOVERED + dt.timedelta(**delta))


# =========================================================================== S2: validity facts follow from the dates
def test_defaults_match_the_agent():
    assert fs_record.DEFAULT_EXPIRING_DAYS == x509_parse.DEFAULT_EXPIRING_DAYS == scan_config.DEFAULT_EXPIRING_DAYS


def test_the_reviewed_example_is_rejected():
    """not_after in 2000 but 'valid' with plenty of days: accepted before S2."""
    record = claiming("valid", 5000, not_after="2000-01-01T00:00:00Z")
    assert rejection(record) == "validity_status_mismatch"


@pytest.mark.parametrize("status, days, flag, code", [
    ("valid", 100, False, None),                      # 100 days left, default threshold 30
    ("expiring", 100, False, "validity_status_mismatch"),
    ("expired", 100, False, "validity_status_mismatch"),
    ("valid", 99, False, "days_to_expiry_mismatch"),
    ("valid", 101, False, "days_to_expiry_mismatch"),
    ("valid", -100, False, "days_to_expiry_mismatch"),
    ("valid", 100, True, "not_yet_valid_mismatch"),
])
def test_each_claim_is_checked_against_the_dates(status, days, flag, code):
    record = claiming(status, days, flag, not_after=after_discovery(days=100, hours=3))
    if code is None:
        validate_fs_record(record)
    else:
        assert rejection(record) == code


def test_expired_certificates_must_say_so():
    gone = after_discovery(days=-10, hours=-3)
    validate_fs_record(claiming("expired", -11, not_after=gone))
    assert rejection(claiming("valid", -11, not_after=gone)) == "validity_status_mismatch"
    assert rejection(claiming("expiring", -11, not_after=gone)) == "validity_status_mismatch"
    assert rejection(claiming("expired", 11, not_after=gone)) == "days_to_expiry_mismatch"


def test_expiring_soon_certificates_are_expiring_not_valid():
    soon = after_discovery(days=5, hours=2)
    validate_fs_record(claiming("expiring", 5, not_after=soon))
    assert rejection(claiming("valid", 5, not_after=soon)) == "validity_status_mismatch"


def test_not_yet_valid_follows_not_before():
    future = after_discovery(days=2)
    validate_fs_record(claiming("valid", 100, True, not_before=future, not_after=after_discovery(days=100, hours=3)))
    assert rejection(claiming("valid", 100, False, not_before=future, not_after=after_discovery(days=100, hours=3))) \
        == "not_yet_valid_mismatch"
    validate_fs_record(claiming("valid", 100, False, not_before=after_discovery(days=-2), not_after=after_discovery(days=100, hours=3)))


def test_mixed_claims_that_are_each_possible_but_not_together_are_rejected():
    boundary = stamp(DISCOVERED)                                  # now == not_after to the second
    validate_fs_record(claiming("expiring", 0, not_after=boundary))               # the clock had not yet passed it
    validate_fs_record(claiming("expired", -1, not_after=boundary))               # the clock had just passed it
    assert rejection(claiming("expired", 0, not_after=boundary)) == "validity_facts_inconsistent"
    assert rejection(claiming("expiring", -1, not_after=boundary)) == "validity_facts_inconsistent"
    assert rejection(claiming("valid", 0, not_after=boundary)) == "validity_status_mismatch"


def test_whole_second_boundaries_accept_both_honest_answers_and_nothing_else():
    """discovered_at is truncated to the second, so the agent's real clock was up to one second later."""
    exactly_31_days = after_discovery(days=31)
    validate_fs_record(claiming("valid", 31, not_after=exactly_31_days))          # clock at the stamp
    validate_fs_record(claiming("expiring", 30, not_after=exactly_31_days))       # clock a moment later
    assert rejection(claiming("valid", 30, not_after=exactly_31_days)) == "validity_facts_inconsistent"
    assert rejection(claiming("expiring", 31, not_after=exactly_31_days)) == "validity_facts_inconsistent"
    assert rejection(claiming("valid", 29, not_after=exactly_31_days)) in ("days_to_expiry_mismatch", "validity_facts_inconsistent")
    one_second_left = after_discovery(seconds=1)
    validate_fs_record(claiming("expiring", 0, not_after=one_second_left))
    assert rejection(claiming("expired", -1, not_after=one_second_left)) == "validity_status_mismatch"


def test_not_before_boundary():
    validate_fs_record(claiming("valid", 100, False, not_before=stamp(DISCOVERED), not_after=after_discovery(days=100, hours=3)))
    assert rejection(claiming("valid", 100, True, not_before=stamp(DISCOVERED), not_after=after_discovery(days=100, hours=3))) \
        == "not_yet_valid_mismatch"
    validate_fs_record(claiming("valid", 100, True, not_before=after_discovery(seconds=1), not_after=after_discovery(days=100, hours=3)))


def test_the_expiring_threshold_comes_from_the_run_configuration():
    sixty_days = after_discovery(days=60, hours=3)
    validate_fs_record(claiming("valid", 60, not_after=sixty_days))                               # default 30
    assert rejection(claiming("expiring", 60, not_after=sixty_days)) == "validity_status_mismatch"
    validate_fs_record(claiming("expiring", 60, not_after=sixty_days), expiring_days=90)
    assert rejection(claiming("valid", 60, not_after=sixty_days), expiring_days=90) == "validity_status_mismatch"
    validate_fs_record(claiming("valid", 60, not_after=sixty_days), expiring_days=0)
    validate_fs_record(claiming("expiring", 60, not_after=sixty_days), expiring_days=60)           # inclusive, like the agent


@pytest.mark.parametrize("config, expected", [({}, 30), ({"expiring_days": 90}, 90), ({"expiring_days": 0}, 0),
                                              ({"expiring_days": -1}, 30), ({"expiring_days": True}, 30),
                                              ({"expiring_days": "90"}, 30), ({"expiring_days": 1.5}, 30),
                                              ({"expiring_days": 10**9}, 30), (None, 30), ("x", 30), ([], 30)])
def test_expiring_days_from_config(config, expected):
    assert fs_record.expiring_days_from_config(config) == expected


def test_ingestion_uses_the_runs_own_expiring_days(conn):
    sixty_days = after_discovery(days=60, hours=3)
    for config, status, accepted in (({}, "valid", 1), ({}, "expiring", 0), ({"expiring_days": 90}, "expiring", 1),
                                     ({"expiring_days": 90}, "valid", 0)):
        run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config=config)
        runs.start_run(conn, run_id, now=at(1))
        result = ingest(conn, run_id, [claiming(status, 60, not_after=sixty_days)])
        assert result.accepted == accepted, (config, status)
        if not accepted:
            assert result.rejected == ((0, "validity_status_mismatch"),)


def test_an_agent_that_used_another_threshold_than_the_run_asked_for_is_visible(conn, tmp_path):
    """Real scan with expiring_days far larger than the run's: honest records would say 'expiring', the run expects 'valid'."""
    put(tmp_path, "a.pem", pemgen.pem_encode(pfxgen.chain()[2]))
    records, scan_summary = run_scan(tmp_path, expiring_days=100_000)
    assert records[0]["validity_status"] == "expiring"
    wrong = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": [str(tmp_path)]})
    runs.start_run(conn, wrong, now=at(1))
    assert ingest(conn, wrong, records).rejected == ((0, "validity_status_mismatch"),)
    right = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": [str(tmp_path)], "expiring_days": 100_000})
    runs.start_run(conn, right, now=at(1))
    assert ingest(conn, right, records).accepted == 1


def test_contradictory_records_are_rejected_cleanly_and_the_batch_continues(conn):
    run_id = running_run(conn)
    bad = claiming("valid", 5000, not_after="2000-01-01T00:00:00Z")
    result = ingest(conn, run_id, [ok_record(r"C:\a\1.pem", n=1), bad, ok_record(r"C:\a\3.pem", n=3)])
    assert result.accepted == 2 and result.rejected == ((1, "validity_status_mismatch"),)
    assert conn.execute("SELECT COUNT(*) FROM fs_observations").fetchone()[0] == 2
    assert finish(conn, run_id, 3).error_summary == "records_rejected:1"


def test_non_ok_records_are_not_subject_to_validity_checks():
    validate_fs_record(failure_record())
    assert rejection(failure_record(validity_status="valid")) == "failure_with_certificate_fields"


def test_real_phase_1_records_always_pass(conn, tmp_path):
    for i, der in enumerate(pfxgen.chain()):
        put(tmp_path, f"c{i}.pem", pemgen.pem_encode(der))
    put(tmp_path, "store.pfx", pfxgen.plain_with_key())
    records, scan_summary = run_scan(tmp_path)
    assert len(records) == 6
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": [str(tmp_path)]})
    runs.start_run(conn, run_id, now=at(1))
    assert ingest(conn, run_id, records).accepted == 6


def grid_possibilities(not_before, not_after, discovered_at, expiring_days):
    """Independent oracle: ask Phase 1's own function at many instants inside the truncated second."""
    base = dt.datetime.strptime(discovered_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    nb = dt.datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    na = dt.datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    out = set()
    for micro in list(range(0, 1_000_000, 50_000)) + [999_999]:
        v = assess_validity(nb, na, base + dt.timedelta(microseconds=micro), expiring_days)
        out.add((v.status, v.days_to_expiry, v.not_yet_valid))
    return out


def random_case(rng):
    real_now = dt.datetime(2026, 1, 1, tzinfo=UTC) + dt.timedelta(seconds=rng.randint(0, 3 * 10**7), microseconds=rng.randint(0, 999_999))
    whole = real_now.replace(microsecond=0)
    if rng.random() < 0.6:                                         # hug the boundaries that matter
        na = whole + dt.timedelta(days=rng.choice([-31, -1, 0, 1, 30, 31, 90]), seconds=rng.choice([-2, -1, 0, 1, 2]))
        nb = whole + dt.timedelta(seconds=rng.choice([-2, -1, 0, 1, 2]) + rng.choice([0, 0, -86400, 86400]))
    else:
        na = whole + dt.timedelta(seconds=rng.randint(-10**7, 10**7))
        nb = whole + dt.timedelta(seconds=rng.randint(-10**7, 10**7))
    return real_now, nb, na, rng.choice([0, 1, 7, 30, 90])


def test_honest_agent_output_is_never_rejected_property():
    rng = random.Random(20261009)
    for _ in range(4000):
        real_now, nb, na, expiring = random_case(rng)
        verdict = assess_validity(nb, na, real_now, expiring)
        record = ok_record(n=1, discovered_at=stamp(real_now), not_before=stamp(nb), not_after=stamp(na),
                           validity_status=verdict.status, days_to_expiry=verdict.days_to_expiry,
                           not_yet_valid=verdict.not_yet_valid)
        validate_fs_record(record, expiring_days=expiring)             # must not raise


def test_validator_agrees_with_an_independent_oracle_on_perturbed_claims_property():
    rng = random.Random(20261010)
    accepted = rejected = 0
    for _ in range(4000):
        real_now, nb, na, expiring = random_case(rng)
        verdict = assess_validity(nb, na, real_now, expiring)
        claim = (rng.choice(["valid", "expiring", "expired"]), verdict.days_to_expiry + rng.choice([-1, 0, 0, 1]),
                 rng.choice([True, False, verdict.not_yet_valid]))
        record = ok_record(n=1, discovered_at=stamp(real_now), not_before=stamp(nb), not_after=stamp(na),
                           validity_status=claim[0], days_to_expiry=claim[1], not_yet_valid=claim[2])
        expected = claim in grid_possibilities(stamp(nb), stamp(na), stamp(real_now), expiring)
        try:
            validate_fs_record(record, expiring_days=expiring)
            actual = True
        except RecordRejected:
            actual = False
        assert actual == expected, (claim, stamp(real_now), stamp(nb), stamp(na), expiring)
        accepted += actual
        rejected += not actual
    assert accepted > 300 and rejected > 300                            # both outcomes were exercised


# ---------------------------------------------------------------- S2: confidence follows from warnings
def test_warnings_lower_confidence_and_none_means_high():
    validate_fs_record(ok_record(n=1, warnings=[], evidence_confidence="high"))
    validate_fs_record(ok_record(n=1, warnings=["serial_not_positive"], evidence_confidence="medium"))


@pytest.mark.parametrize("warnings, confidence", [(["serial_not_positive"], "high"), ([], "medium"), ([], "low"),
                                                   (["serial_not_positive"], "low")])
def test_inconsistent_confidence_is_rejected(warnings, confidence):
    assert rejection(ok_record(n=1, warnings=warnings, evidence_confidence=confidence)) == "confidence_warnings_mismatch"


def test_the_integrity_warning_keeps_its_specific_rejection_code():
    assert rejection(pfx_record(warnings=["pkcs12_integrity_not_verified"], evidence_confidence="high")) \
        == "integrity_warning_with_high_confidence"
    assert rejection(pfx_record(warnings=["pkcs12_integrity_not_verified"], evidence_confidence="low")) == "confidence_warnings_mismatch"


def test_inconsistent_confidence_never_reaches_the_database(conn):
    run_id = running_run(conn)
    result = ingest(conn, run_id, [ok_record(n=1, warnings=["serial_not_positive"], evidence_confidence="high"),
                                   ok_record(r"C:\a\2.pem", n=2, warnings=["serial_not_positive"])])
    assert result.accepted == 1 and result.rejected == ((0, "confidence_warnings_mismatch"),)


# =========================================================================== S4: conflicting replays
def issues(conn, run_id, kind=None):
    return [i for i in fs_queries.list_run_issues(conn, run_id) if kind is None or i["kind"] == kind]


def test_a_conflicting_replay_is_reported_as_a_conflict_not_a_rejection(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\a\one.pem", n=1)])
    result = ingest(conn, run_id, [ok_record(r"C:\a\two.pem", n=2)])
    assert result == fs_ingest.BatchResult(accepted=0, duplicates=0, rejected=(), conflicts=(0,))
    [issue] = issues(conn, run_id)
    assert (issue["source"], issue["kind"], issue["code"], issue["seq"], issue["path"]) == (
        "backend", "seq_conflict", "seq_conflict", 0, r"C:\a\two.pem")
    stored = runs.get_run(conn, run_id)
    assert stored["rejected_count"] == 0 and stored["record_count"] == 1
    assert fs_queries.list_fs_observations(conn, run_id)[0]["path"] == r"C:\a\one.pem"          # first write stands


def test_an_invalid_replay_of_a_stored_seq_is_a_conflict_too(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    first = ingest(conn, run_id, [{"junk": 1}])
    assert first.conflicts == (0,) and first.rejected == ()
    for bad in ("not a dict", ok_record(n=1, key_size=0)):                          # the conflict is already on record
        assert ingest(conn, run_id, [bad]) == fs_ingest.BatchResult(0, 1, ())
    assert len(issues(conn, run_id, "seq_conflict")) == 1 and issues(conn, run_id, "rejected_record") == []
    other = running_run(conn)
    ingest(conn, other, [ok_record(n=1)])
    assert ingest(conn, other, [ok_record(n=1, key_size=0)]).conflicts == (0,)         # a record that fails validation


def test_an_invalid_record_for_an_unused_seq_is_still_an_ordinary_rejection(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    result = ingest(conn, run_id, [{"junk": 1}], start=1)
    assert result.rejected == ((1, "unknown_field"),) and result.conflicts == ()
    assert [i["kind"] for i in issues(conn, run_id)] == ["rejected_record"]


def test_exact_replays_stay_silent(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    assert ingest(conn, run_id, [ok_record(n=1)]) == fs_ingest.BatchResult(0, 1, ())
    assert issues(conn, run_id) == []


def test_a_conflict_is_recorded_once_per_seq_however_often_it_is_replayed(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(r"C:\a\one.pem", n=1)])
    ingest(conn, run_id, [ok_record(r"C:\a\two.pem", n=2)])
    again = ingest(conn, run_id, [ok_record(r"C:\a\two.pem", n=2)])                  # same contradiction again
    other = ingest(conn, run_id, [ok_record(r"C:\a\three.pem", n=3)])                # a different contradiction
    assert again == fs_ingest.BatchResult(0, 1, ()) and other == fs_ingest.BatchResult(0, 1, ())
    assert len(issues(conn, run_id)) == 1 and fs_ingest.seq_conflict_count(conn, run_id) == 1


def test_conflicts_in_one_batch_and_across_batches(conn):
    run_id = running_run(conn)
    result = fs_ingest.ingest_fs_batch(conn, run_id, [(0, ok_record(r"C:\a\1.pem", n=1)), (0, ok_record(r"C:\a\x.pem", n=9)),
                                                      (1, ok_record(r"C:\a\2.pem", n=2))], now=at(2))
    assert (result.accepted, result.conflicts) == (2, (0,))
    later = fs_ingest.ingest_fs_batch(conn, run_id, [(1, ok_record(r"C:\a\y.pem", n=8))], now=at(3))
    assert later.conflicts == (1,) and fs_ingest.seq_conflict_count(conn, run_id) == 2


def test_a_rejected_seq_stays_rejected_and_is_not_a_conflict(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [{"junk": 1}])
    assert ingest(conn, run_id, [ok_record(n=1)]) == fs_ingest.BatchResult(0, 1, ())
    assert [i["kind"] for i in issues(conn, run_id)] == ["rejected_record"] and fs_ingest.seq_conflict_count(conn, run_id) == 0


def test_conflicts_do_not_count_as_rejected_records(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), ok_record(r"C:\a\2.pem", n=2)])
    ingest(conn, run_id, [ok_record(r"C:\a\z.pem", n=7)])                             # conflict on seq 0
    ingest(conn, run_id, [{"junk": 1}], start=2)                                      # genuine rejection on seq 2
    counts = fs_ingest.derived_counts(conn, run_id)
    assert (counts.records, counts.rejected) == (2, 1)
    summary_counts = fs_queries.fs_counts(conn, run_id)
    assert (summary_counts.rejected, summary_counts.seq_conflicts, summary_counts.observations) == (1, 1, 2)
    assert fs_ingest._distinct_seqs_seen(conn, run_id) == 3                          # seq 0, 1 stored; seq 2 rejected


def test_a_run_with_a_conflict_is_partial_with_its_own_reason(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), ok_record(r"C:\a\2.pem", n=2)])
    ingest(conn, run_id, [ok_record(r"C:\a\z.pem", n=7)])
    final = finish(conn, run_id, 2)
    assert final.status == "partial" and final.error_summary == "seq_conflicts:1"
    assert (final.record_count, final.finding_count, final.rejected_count, final.error_count) == (2, 2, 0, 0)
    assert runs.get_run(conn, run_id)["stop_reason"] == "completed"


def test_a_clean_replay_does_not_make_the_run_partial(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    ingest(conn, run_id, [ok_record(n=1)])
    assert finish(conn, run_id, 1).status == "completed"


def test_conflicts_and_rejections_are_reported_separately_and_in_order(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), ok_record(r"C:\a\2.pem", n=2)])
    ingest(conn, run_id, [ok_record(r"C:\a\z.pem", n=7)])                              # conflict (seq 0)
    ingest(conn, run_id, [ok_record(r"C:\a\w.pem", n=8)], start=1)                     # conflict (seq 1)
    ingest(conn, run_id, [{"junk": 1}], start=2)                                       # rejection (seq 2)
    final = finish(conn, run_id, 3)
    assert final.error_summary == "records_rejected:1, seq_conflicts:2"
    assert final.status == "partial" and final.rejected_count == 1


def test_a_conflict_is_reported_even_when_the_agent_sent_no_summary(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    ingest(conn, run_id, [ok_record(r"C:\z.pem", n=7)])
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(5), outcome="lost")
    assert final.status == "partial" and final.error_summary == "agent_lost, seq_conflicts:1"
    other = running_run(conn)
    ingest(conn, other, [ok_record(n=1)])
    ingest(conn, other, [ok_record(r"C:\z.pem", n=7)])
    assert fs_ingest.finalize_fs_run(conn, other, now=at(5), summary=None).error_summary == "stop_reason_missing, seq_conflicts:1"


def test_the_conflict_count_is_per_seq_even_if_issue_rows_were_duplicated(conn):
    """Defence in depth: one issue per seq is the rule, but the count must not depend on it."""
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    ingest(conn, run_id, [ok_record(r"C:\z.pem", n=7)])
    conn.execute("INSERT INTO run_issues (run_id, source, kind, code, seq) VALUES (?, 'backend', 'seq_conflict', 'seq_conflict', 0)", (run_id,))
    assert fs_ingest.seq_conflict_count(conn, run_id) == 1 and fs_queries.fs_counts(conn, run_id).seq_conflicts == 1


def test_conflicts_do_not_cause_a_count_mismatch(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    ingest(conn, run_id, [ok_record(r"C:\a\z.pem", n=7)])
    assert "count_mismatch" not in finish(conn, run_id, 1).error_summary


def test_a_conflict_is_rolled_back_with_a_failed_batch(conn, monkeypatch):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    monkeypatch.setattr(fs_ingest, "_renumber_ordinals", lambda *a: (_ for _ in ()).throw(RuntimeError("x")))
    with pytest.raises(RuntimeError):
        ingest(conn, run_id, [ok_record(r"C:\a\z.pem", n=7), ok_record(r"C:\a\2.pem", n=2)], start=0)
    monkeypatch.undo()
    assert issues(conn, run_id) == [] and fs_ingest.seq_conflict_count(conn, run_id) == 0


def test_a_conflict_lookup_uses_the_index(conn):
    detail = " ".join(r["detail"] for r in conn.execute("EXPLAIN QUERY PLAN " + fs_ingest.REJECTED_LOOKUP_SQL, ("r", "seq_conflict", 1)))
    assert "idx_run_issues_kind_seq" in detail


def test_run_state_seq_conflicts():
    clean = rs.AgentReport(outcome="finished", stop_reason="completed", coverage_started=True)
    assert rs.decide_outcome(rs.Counts(records=3), clean) == ("completed", ())
    with_conflicts = rs.AgentReport(outcome="finished", stop_reason="completed", coverage_started=True, seq_conflicts=2)
    assert rs.decide_outcome(rs.Counts(records=3), with_conflicts) == ("partial", ("seq_conflicts:2",))
    assert rs.decide_outcome(rs.Counts(records=3, rejected=1, errors=1), with_conflicts) == (
        "partial", ("file_errors:1", "records_rejected:1", "seq_conflicts:2"))
    nothing_scanned = rs.AgentReport(outcome="finished", stop_reason="completed", coverage_started=False, seq_conflicts=2)
    assert rs.decide_outcome(rs.Counts(records=0), nothing_scanned)[0] == "failed"        # a conflict cannot rescue an empty run
    for bad in (-1, 1.5, True, "1", None):
        with pytest.raises(ValueError):
            rs.AgentReport(outcome="finished", seq_conflicts=bad)


# =========================================================================== S5: read errors affect the status
READ_CODE = "PermissionError:WinError 5"


def read_error(path, code=READ_CODE):
    return dir_error(path, "read", code)


def test_a_read_error_without_any_stored_observation_makes_the_run_partial(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    final = finish(conn, run_id, 1, summary=summary(1, errors=[read_error(r"C:\app\locked.pem")]))
    assert final.status == "partial" and final.error_summary == "file_errors:1" and final.error_count == 1


def test_a_resolved_read_error_is_counted_once(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), failure_record(r"C:\app\locked.pem", "access_denied")])
    final = finish(conn, run_id, 2, summary=summary(2, errors=[read_error(r"C:\app\locked.pem")]))
    assert final.status == "partial" and final.error_count == 1 and final.error_summary == "file_errors:1"
    assert fs_ingest._unresolved_read_errors(conn, run_id) == 0


def test_a_read_error_is_resolved_by_a_read_error_status_too(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [failure_record(r"C:\app\gone.pem", "read_error", access_error="FileNotFoundError:WinError 2")])
    final = finish(conn, run_id, 1, summary=summary(1, errors=[read_error(r"C:\app\gone.pem", "FileNotFoundError:WinError 2")]))
    assert final.error_count == 1 and final.status == "partial"


@pytest.mark.parametrize("kind", ["root", "listdir", "stat", "read"])
def test_every_kind_of_agent_error_makes_the_run_partial(conn, kind):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    final = finish(conn, run_id, 1, summary=summary(1, errors=[dir_error(r"C:\app\x", kind)]))
    assert final.status == "partial" and final.error_summary == "file_errors:1" and final.error_count == 1


@pytest.mark.parametrize("record, why", [
    (failure_record(r"C:\app\locked.pem", "access_denied", access_error="PermissionError:WinError 32"), "different error code"),
    (failure_record(r"C:\app\other.pem", "access_denied"), "different path"),
    (failure_record(r"C:\app\locked.pem", "malformed", access_error=None, detail="x509_malformed: truncated"), "not an error status"),
    (failure_record(r"C:\app\locked.pem", "access_denied", access_error=None), "record carries no error code"),
])
def test_a_read_error_the_stored_evidence_does_not_explain_stays_unresolved(conn, record, why):
    run_id = running_run(conn)
    ingest(conn, run_id, [record])
    counts_before = fs_ingest.derived_counts(conn, run_id)
    final = finish(conn, run_id, 1, summary=summary(1, errors=[read_error(r"C:\app\locked.pem")]))
    expected = counts_before.errors + 1
    assert final.error_count == expected and final.status == "partial", why


def test_only_error_statuses_resolve_a_read_error_even_when_path_and_code_match(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [failure_record(r"C:pp\locked.pem", "malformed", access_error=READ_CODE, detail="x509_malformed: truncated")])
    assert fs_ingest.derived_counts(conn, run_id).errors == 0                         # a malformed file is not a read error
    final = finish(conn, run_id, 1, summary=summary(1, errors=[read_error(r"C:pp\locked.pem")]))
    assert final.error_count == 1 and final.status == "partial"


def test_a_read_error_whose_record_was_rejected_is_unresolved(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [failure_record(r"C:\app\locked.pem", "access_denied", evidence_confidence="high")])      # invalid
    final = finish(conn, run_id, 1, summary=summary(1, errors=[read_error(r"C:\app\locked.pem")]))
    assert final.rejected_count == 1 and final.error_count == 1
    assert final.status == "failed" and final.error_summary.startswith("no_usable_data")


def test_mixed_resolved_and_unresolved_read_errors(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), failure_record(r"C:\app\a.pem", "access_denied"),
                          failure_record(r"C:\app\b.pem", "access_denied")])
    errors = [read_error(r"C:\app\a.pem"), read_error(r"C:\app\b.pem"), read_error(r"C:\app\c.pem"), dir_error(r"C:\app\d", "listdir")]
    final = finish(conn, run_id, 3, summary=summary(3, errors=errors))
    assert final.error_count == 2 + 1 + 1 and final.error_summary == "file_errors:4"


def test_reconciliation_is_by_path_so_sanitised_paths_match(conn):
    run_id = running_run(conn)
    path = "C:\\app\\bad\ud800name.pem"
    ingest(conn, run_id, [ok_record(n=1), failure_record(path, "access_denied")])
    final = finish(conn, run_id, 2, summary=summary(2, errors=[read_error(path)]))
    assert final.error_count == 1


def test_resolution_does_not_depend_on_arrival_order(conn):
    forward, backward = running_run(conn), running_run(conn)
    records = [ok_record(n=1), failure_record(r"C:\app\a.pem", "access_denied"), failure_record(r"C:\app\b.pem", "access_denied")]
    errors = [read_error(r"C:\app\a.pem"), read_error(r"C:\app\b.pem")]
    ingest(conn, forward, records)
    for pair in reversed(list(enumerate(records))):
        fs_ingest.ingest_fs_batch(conn, backward, [pair], now=at(2))
    assert [finish(conn, r, 3, summary=summary(3, errors=errors)).error_count for r in (forward, backward)] == [2, 2]


def test_a_read_error_is_stored_as_an_agent_issue_whether_or_not_it_is_resolved(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    finish(conn, run_id, 1, summary=summary(1, errors=[read_error(r"C:\app\locked.pem")]))
    assert [(i["source"], i["kind"], i["path"]) for i in issues(conn, run_id)] == [("agent", "read", r"C:\app\locked.pem")]


def test_a_real_locked_file_is_counted_exactly_once(conn, tmp_path):
    from treegen import exclusive_lock
    put(tmp_path, "ok.pem", pemgen.pem_encode(pfxgen.chain()[2]))
    locked = put(tmp_path, "locked.pem", pemgen.pem_encode(pfxgen.chain()[2]))
    with exclusive_lock(locked):
        records, scan_summary = run_scan(tmp_path)
    assert [e["kind"] for e in scan_summary["errors"]] == ["read"]
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": [str(tmp_path)]})
    runs.start_run(conn, run_id, now=at(1))
    fs_ingest.ingest_fs_batch(conn, run_id, fs_ingest.number_records(records), now=at(2))
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(3), summary=scan_summary)
    assert final.status == "partial" and final.error_count == 1 and fs_ingest._unresolved_read_errors(conn, run_id) == 0


def test_a_real_run_where_the_record_was_lost_in_transit_is_partial(conn, tmp_path):
    from treegen import exclusive_lock
    put(tmp_path, "ok.pem", pemgen.pem_encode(pfxgen.chain()[2]))
    locked = put(tmp_path, "locked.pem", pemgen.pem_encode(pfxgen.chain()[2]))
    with exclusive_lock(locked):
        records, scan_summary = run_scan(tmp_path)
    kept = [r for r in records if r["parse_status"] != "access_denied"]            # the error record never arrived
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": [str(tmp_path)]})
    runs.start_run(conn, run_id, now=at(1))
    fs_ingest.ingest_fs_batch(conn, run_id, fs_ingest.number_records(kept), now=at(2))
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(3), summary=scan_summary)
    assert final.status == "partial" and final.error_count == 1
    assert "file_errors:1" in final.error_summary and "count_mismatch" in final.error_summary


# =========================================================================== S6: scan policy is not failure (pinned)
POLICY_SKIPS = {"depth_limit": 3, "excluded_dir": 2, "reparse_dir": 1, "reparse_file": 1, "cloud_placeholder": 4,
                "not_regular_file": 1, "root_overlap": 1}


def test_policy_skips_oversize_files_and_overlap_never_make_a_run_partial(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1),
                          failure_record(r"C:\app\big.pem", "too_large", access_error=None, detail="file_too_large"),
                          failure_record(r"C:\app\cloud.pem", "skipped", access_error=None, detail="cloud_placeholder")])
    final = finish(conn, run_id, 3, summary=summary(3, skipped=POLICY_SKIPS, roots=((r"C:\app", "scanned"), (r"C:\app\sub", "overlap"))))
    assert final.status == "completed" and final.error_summary is None and final.error_count == 0
    kept = runs.get_run(conn, run_id)["agent_summary"]["skipped"]
    assert kept == POLICY_SKIPS                                                   # still visible as coverage information
    assert fs_queries.fs_counts(conn, run_id).by_parse_status == {"ok": 1, "too_large": 1, "skipped": 1}


def test_the_real_scanner_policy_boundaries_leave_the_run_completed(conn, tmp_path):
    cert = pemgen.pem_encode(pfxgen.chain()[2])
    put(tmp_path, "top.pem", cert)
    put(tmp_path, "deep/inner/hidden.pem", cert)                                   # beyond max_depth=1
    put(tmp_path, "skipme/excluded.pem", cert)                                     # excluded directory
    put(tmp_path, "huge.pem", cert + b"#" * 4096)                                  # over the size limit
    records, scan_summary = run_scan(tmp_path, max_depth=1, exclude_dir_names=("skipme",), max_file_bytes=2000)
    assert scan_summary["skipped"].get("depth_limit") and scan_summary["skipped"].get("excluded_dir")
    assert any(r["parse_status"] == "too_large" for r in records) and scan_summary["stop_reason"] == "completed"
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": [str(tmp_path)]})
    runs.start_run(conn, run_id, now=at(1))
    fs_ingest.ingest_fs_batch(conn, run_id, fs_ingest.number_records(records), now=at(2))
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(3), summary=scan_summary)
    assert final.status == "completed" and final.error_summary is None
    assert runs.get_run(conn, run_id)["agent_summary"]["skipped"] == {k: v for k, v in scan_summary["skipped"].items()}


def test_the_real_scanner_symlink_and_junction_skips_leave_the_run_completed(conn, tmp_path):
    from treegen import make_junction
    cert = pemgen.pem_encode(pfxgen.chain()[2])
    put(tmp_path, "real/a.pem", cert)
    if not make_junction(tmp_path / "link", tmp_path / "real"):
        pytest.skip("cannot create a junction here")
    records, scan_summary = run_scan(tmp_path)
    assert scan_summary["skipped"].get("reparse_dir")
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": [str(tmp_path)]})
    runs.start_run(conn, run_id, now=at(1))
    fs_ingest.ingest_fs_batch(conn, run_id, fs_ingest.number_records(records), now=at(2))
    assert fs_ingest.finalize_fs_run(conn, run_id, now=at(3), summary=scan_summary).status == "completed"


def test_the_policy_is_documented_in_the_module():
    text = fs_ingest.__doc__
    assert "Scan policy is not failure" in text and "depth_limit" in text and "Read errors" in text
