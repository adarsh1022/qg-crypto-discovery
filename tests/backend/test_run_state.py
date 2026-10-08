"""The run lifecycle as pure functions: transitions, outcome rules, durations, counts, timeouts."""
import dataclasses
import datetime as dt
import itertools

import pytest

from backend import run_state as rs
from backend.run_state import AgentReport, Counts, InvalidTransition, RunState

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)


def at(seconds=0.0):
    return T0 + dt.timedelta(seconds=seconds)


def running(**fields):
    return dataclasses.replace(rs.start(rs.new_run(T0), at(1)), **fields)


CLEAN = AgentReport(outcome="finished", stop_reason="completed", coverage_started=True)


# ------------------------------------------------------------------ the transition table
def test_status_vocabulary_is_the_five_required_states():
    assert rs.STATUSES == ("queued", "running", "completed", "partial", "failed")
    assert rs.TERMINAL == {"completed", "partial", "failed"}


@pytest.mark.parametrize("src, dst", list(itertools.product(rs.STATUSES, rs.STATUSES)))
def test_can_transition_table(src, dst):
    allowed = {("queued", "running"), ("queued", "failed"),
               ("running", "completed"), ("running", "partial"), ("running", "failed")}
    assert rs.can_transition(src, dst) == ((src, dst) in allowed)


def test_unknown_status_cannot_transition():
    assert not rs.can_transition("paused", "running")
    assert not rs.can_transition("queued", "paused")


# ------------------------------------------------------------------ new / start / heartbeat
def test_new_run_is_queued_and_empty():
    run = rs.new_run(T0)
    assert run == RunState(status="queued", queued_at="2026-03-01T12:00:00.000Z")
    assert run.started_at is None and run.finished_at is None and run.duration_ms is None
    assert (run.record_count, run.finding_count, run.rejected_count, run.error_count) == (0, 0, 0, 0)


def test_start_sets_running_started_and_heartbeat():
    run = rs.start(rs.new_run(T0), at(2.5))
    assert run.status == "running"
    assert run.started_at == run.last_heartbeat_at == "2026-03-01T12:00:02.500Z"
    assert run.finished_at is None and run.duration_ms is None


def test_functions_return_new_objects_and_never_mutate():
    queued = rs.new_run(T0)
    started = rs.start(queued, at(1))
    assert queued.status == "queued" and started is not queued
    with pytest.raises(dataclasses.FrozenInstanceError):
        queued.status = "running"


@pytest.mark.parametrize("status", ["running", "completed", "partial", "failed"])
def test_cannot_start_a_run_that_is_not_queued(status):
    run = dataclasses.replace(rs.new_run(T0), status=status)
    with pytest.raises(InvalidTransition):
        rs.start(run, at(1))


def test_heartbeat_updates_only_the_heartbeat():
    run = running()
    beat = rs.heartbeat(run, at(30))
    assert beat.last_heartbeat_at == "2026-03-01T12:00:30.000Z"
    assert beat.started_at == run.started_at and beat.status == "running"


@pytest.mark.parametrize("status", ["queued", "completed", "partial", "failed"])
def test_heartbeat_requires_a_running_run(status):
    with pytest.raises(InvalidTransition):
        rs.heartbeat(dataclasses.replace(rs.new_run(T0), status=status), at(5))


def test_naive_datetimes_are_refused():
    with pytest.raises(ValueError):
        rs.new_run(dt.datetime(2026, 3, 1))
    with pytest.raises(ValueError):
        rs.start(rs.new_run(T0), dt.datetime(2026, 3, 1))


def test_non_utc_input_is_normalized_to_utc():
    plus_two = dt.timezone(dt.timedelta(hours=2))
    assert rs.format_ts(dt.datetime(2026, 3, 1, 14, 0, 0, 123456, tzinfo=plus_two)) == "2026-03-01T12:00:00.123Z"


def test_timestamps_round_trip_and_sort_lexicographically():
    moments = [at(0), at(0.001), at(0.999), at(1), at(59.5), at(3600)]
    stamps = [rs.format_ts(m) for m in moments]
    assert stamps == sorted(stamps)
    assert [rs.parse_ts(s) for s in stamps] == [m.replace(microsecond=m.microsecond // 1000 * 1000) for m in moments]


# ------------------------------------------------------------------ counts
def test_update_counts_sets_the_four_counters_while_running():
    run = rs.update_counts(running(), Counts(records=10, findings=8, rejected=1, errors=2))
    assert (run.record_count, run.finding_count, run.rejected_count, run.error_count) == (10, 8, 1, 2)
    assert rs.update_counts(run, Counts(records=11)).record_count == 11            # replaced, not accumulated


@pytest.mark.parametrize("status", ["queued", "completed", "partial", "failed"])
def test_update_counts_requires_a_running_run(status):
    with pytest.raises(InvalidTransition):
        rs.update_counts(dataclasses.replace(rs.new_run(T0), status=status), Counts())


@pytest.mark.parametrize("bad", [-1, 1.5, "3", None, True])
def test_counts_must_be_non_negative_integers(bad):
    for field in ("records", "findings", "rejected", "errors"):
        with pytest.raises(ValueError):
            Counts(**{field: bad})


def test_finish_stores_the_backends_counts():
    done = rs.finish(running(), at(10), Counts(records=7, findings=5, rejected=0, errors=0), CLEAN)
    assert (done.record_count, done.finding_count, done.rejected_count, done.error_count) == (7, 5, 0, 0)


# ------------------------------------------------------------------ duration
def test_duration_is_finish_minus_start_in_milliseconds():
    done = rs.finish(running(), at(1 + 12.345), Counts(records=1), CLEAN)
    assert done.started_at == "2026-03-01T12:00:01.000Z" and done.finished_at == "2026-03-01T12:00:13.345Z"
    assert done.duration_ms == 12345


def test_duration_of_an_instant_run_is_zero():
    assert rs.finish(running(), at(1), Counts(records=1), CLEAN).duration_ms == 0


def test_duration_never_goes_negative_when_the_clock_moves_backwards():
    done = rs.finish(running(), at(-100), Counts(records=1), CLEAN)
    assert done.duration_ms == 0
    assert done.finished_at == done.started_at                                      # finished_at never precedes started_at


def test_duration_ms_helper():
    assert rs.duration_ms("2026-03-01T12:00:00.000Z", "2026-03-01T12:00:00.001Z") == 1
    assert rs.duration_ms("2026-03-01T12:00:00.000Z", "2026-03-02T12:00:00.000Z") == 86_400_000
    assert rs.duration_ms("2026-03-01T12:00:05.000Z", "2026-03-01T12:00:00.000Z") == 0


def test_run_that_never_started_has_no_duration():
    failed = rs.fail(rs.new_run(T0), at(5), "agent_not_connected")
    assert failed.started_at is None and failed.duration_ms is None and failed.finished_at is not None


# ------------------------------------------------------------------ outcome rules
def outcome(counts=Counts(records=3, findings=3), **report):
    base = dict(outcome="finished", stop_reason="completed", coverage_started=True)
    base.update(report)
    return rs.decide_outcome(counts, AgentReport(**base))


def test_clean_full_scan_is_completed():
    assert outcome() == ("completed", ())


def test_clean_scan_that_found_nothing_is_still_completed():
    assert outcome(Counts()) == ("completed", ())


@pytest.mark.parametrize("counts", [Counts(records=5, findings=5, errors=1), Counts(records=5, errors=40)])
def test_file_level_errors_make_the_run_partial(counts):
    status, reasons = outcome(counts)
    assert status == "partial" and reasons == (f"file_errors:{counts.errors}",)


@pytest.mark.parametrize("stop_reason", ["time_limit", "entry_limit", "candidate_limit", "cancelled"])
def test_limits_and_cancellation_make_the_run_partial(stop_reason):
    assert outcome(stop_reason=stop_reason) == ("partial", (f"stopped_{stop_reason}",))


def test_missing_stop_reason_is_not_trusted_as_complete():
    assert outcome(stop_reason=None) == ("partial", ("stop_reason_missing",))


def test_unreached_roots_make_the_run_partial():
    assert outcome(roots_not_scanned=2) == ("partial", ("roots_not_scanned:2",))


def test_truncated_bundles_make_the_run_partial():
    assert outcome(truncated_files=1) == ("partial", ("bundles_truncated:1",))


def test_rejected_records_make_the_run_partial_when_some_data_was_accepted():
    assert outcome(Counts(records=4, findings=4, rejected=2)) == ("partial", ("records_rejected:2",))


def test_count_mismatch_makes_the_run_partial():
    assert outcome(count_mismatch=True) == ("partial", ("count_mismatch",))


def test_agent_loss_after_accepting_data_is_partial():
    status, reasons = outcome(Counts(records=9), outcome="lost", stop_reason=None)
    assert status == "partial" and reasons == ("agent_lost",)


def test_agent_loss_before_any_data_is_failed():
    status, reasons = outcome(Counts(), outcome="lost", stop_reason=None, coverage_started=False)
    assert status == "failed" and reasons == ("no_usable_data", "agent_lost")


def test_fatal_agent_failure_is_failed_even_with_data():
    assert outcome(Counts(records=50), outcome="failed", fatal_code="capture_unavailable") == \
        ("failed", ("capture_unavailable",))


@pytest.mark.parametrize("code", [None, "", "Has Spaces", "x" * 41, "UPPER", "../../etc/passwd", "C:\\secret\\path"])
def test_fatal_code_is_sanitized(code):
    assert outcome(outcome="failed", fatal_code=code) == ("failed", ("agent_failed",))


def test_nothing_scanned_and_nothing_accepted_is_failed():
    status, reasons = outcome(Counts(), coverage_started=False, roots_not_scanned=1)
    assert status == "failed" and reasons == ("no_usable_data", "roots_not_scanned:1")


def test_every_record_rejected_is_failed():
    status, reasons = outcome(Counts(records=0, rejected=6))
    assert status == "failed" and reasons == ("no_usable_data", "records_rejected:6")


def test_scanned_roots_with_no_certificates_but_a_gap_is_partial_not_failed():
    status, _ = outcome(Counts(), stop_reason="time_limit")
    assert status == "partial"


def test_multiple_reasons_are_all_reported_in_a_fixed_order():
    status, reasons = outcome(Counts(records=3, errors=2, rejected=1), stop_reason="entry_limit",
                              roots_not_scanned=1, truncated_files=4, count_mismatch=True)
    assert status == "partial"
    assert reasons == ("stopped_entry_limit", "roots_not_scanned:1", "bundles_truncated:4",
                       "file_errors:2", "records_rejected:1", "count_mismatch")


def test_hostile_stop_reason_cannot_leak_into_the_summary():
    status, reasons = outcome(stop_reason="C:\\Users\\bob\\secret.pfx")
    assert (status, reasons) == ("partial", ("stopped_unknown",))
    done = rs.finish(running(), at(5), Counts(records=1), AgentReport(
        outcome="finished", stop_reason="C:\\Users\\bob\\secret.pfx", coverage_started=True))
    assert "bob" not in (done.error_summary or "") and done.stop_reason is None


@pytest.mark.parametrize("kwargs", [dict(outcome="done"), dict(outcome="finished", roots_not_scanned=-1),
                                    dict(outcome="finished", truncated_files=1.5), dict(outcome="finished", roots_not_scanned=True)])
def test_agent_report_is_validated(kwargs):
    with pytest.raises(ValueError):
        AgentReport(**kwargs)


# ------------------------------------------------------------------ finish
@pytest.mark.parametrize("counts, report, status", [
    (Counts(records=3), CLEAN, "completed"),
    (Counts(records=3, errors=1), CLEAN, "partial"),
    (Counts(), AgentReport(outcome="failed", fatal_code="boom"), "failed"),
])
def test_finish_applies_the_decided_status(counts, report, status):
    done = rs.finish(running(), at(9), counts, report)
    assert done.status == status and done.finished_at is not None and done.duration_ms is not None


def test_completed_run_has_no_error_summary_and_a_clean_stop_reason():
    done = rs.finish(running(), at(9), Counts(records=2), CLEAN)
    assert done.error_summary is None and done.stop_reason == "completed"


def test_partial_and_failed_runs_always_carry_an_error_summary():
    partial = rs.finish(running(), at(9), Counts(records=2, errors=2), CLEAN)
    assert partial.status == "partial" and partial.error_summary == "file_errors:2"
    failed = rs.finish(running(), at(9), Counts(), AgentReport(outcome="failed"))
    assert failed.status == "failed" and failed.error_summary == "agent_failed" and failed.stop_reason == "agent_failed"
    lost = rs.finish(running(), at(9), Counts(records=1), AgentReport(outcome="lost", coverage_started=True))
    assert lost.status == "partial" and lost.stop_reason == "agent_lost" and lost.error_summary == "agent_lost"


def test_finish_records_the_agents_stop_reason():
    done = rs.finish(running(), at(9), Counts(records=2), AgentReport(
        outcome="finished", stop_reason="time_limit", coverage_started=True))
    assert done.stop_reason == "time_limit" and done.error_summary == "stopped_time_limit"


def test_error_summary_is_fixed_codes_only():
    done = rs.finish(running(), at(9), Counts(records=1, errors=3, rejected=1), AgentReport(
        outcome="finished", stop_reason="completed", coverage_started=True, roots_not_scanned=1))
    assert done.error_summary == "roots_not_scanned:1, file_errors:3, records_rejected:1"


@pytest.mark.parametrize("status", ["queued", "completed", "partial", "failed"])
def test_cannot_finish_a_run_that_is_not_running(status):
    with pytest.raises(InvalidTransition):
        rs.finish(dataclasses.replace(rs.new_run(T0), status=status), at(9), Counts(records=1), CLEAN)


def test_terminal_runs_are_immutable():
    done = rs.finish(running(), at(9), Counts(records=1), CLEAN)
    for call in (lambda: rs.start(done, at(10)), lambda: rs.heartbeat(done, at(10)),
                 lambda: rs.finish(done, at(10), Counts(records=1), CLEAN), lambda: rs.fail(done, at(10), "x"),
                 lambda: rs.request_cancel(done, at(10)), lambda: rs.update_counts(done, Counts())):
        with pytest.raises(InvalidTransition):
            call()


# ------------------------------------------------------------------ fail / cancel
def test_fail_from_queued_and_from_running():
    queued = rs.fail(rs.new_run(T0), at(3), "agent_not_connected")
    assert queued.status == "failed" and queued.error_summary == "agent_not_connected" and queued.duration_ms is None
    live = rs.fail(rs.update_counts(running(), Counts(records=4, findings=4)), at(5), "internal_error", Counts(records=4, findings=4))
    assert live.status == "failed" and live.duration_ms == 4000 and live.record_count == 4


def test_fail_code_is_sanitized():
    assert rs.fail(rs.new_run(T0), at(1), "Not A Code!").error_summary == "failed"


def test_cancel_queued_run_fails_it_immediately():
    cancelled = rs.request_cancel(rs.new_run(T0), at(2))
    assert cancelled.status == "failed" and cancelled.stop_reason == "cancelled" and cancelled.error_summary == "cancelled"


def test_cancel_running_run_only_sets_the_flag():
    flagged = rs.request_cancel(running(), at(2))
    assert flagged.status == "running" and flagged.cancel_requested and flagged.finished_at is None
    assert rs.request_cancel(flagged, at(3)) == flagged                              # idempotent while running


def test_cancelled_running_run_ends_partial_when_the_agent_reports_it():
    flagged = rs.request_cancel(running(), at(2))
    done = rs.finish(flagged, at(4), Counts(records=6, findings=6), AgentReport(
        outcome="finished", stop_reason="cancelled", coverage_started=True))
    assert done.status == "partial" and done.stop_reason == "cancelled" and done.cancel_requested


# ------------------------------------------------------------------ timeouts
def test_queued_run_expires_when_no_agent_claims_it():
    run = rs.new_run(T0)
    assert rs.expire(run, at(120), queue_timeout_s=120, heartbeat_timeout_s=90) is None          # exactly at the limit
    expired = rs.expire(run, at(120.001), queue_timeout_s=120, heartbeat_timeout_s=90)
    assert expired.status == "failed" and expired.error_summary == "agent_not_connected" and expired.started_at is None


def test_running_run_expires_when_heartbeats_stop():
    run = rs.heartbeat(running(), at(10))
    assert rs.expire(run, at(100), queue_timeout_s=120, heartbeat_timeout_s=90) is None
    expired = rs.expire(run, at(100.5), queue_timeout_s=120, heartbeat_timeout_s=90)
    assert expired.status == "failed" and "agent_lost" in expired.error_summary and "no_usable_data" in expired.error_summary


def test_lost_run_with_accepted_data_is_partial_and_keeps_its_counts():
    run = rs.update_counts(running(), Counts(records=12, findings=10, rejected=0, errors=1))
    expired = rs.expire(run, at(500), queue_timeout_s=120, heartbeat_timeout_s=90)
    assert expired.status == "partial" and expired.stop_reason == "agent_lost"
    assert (expired.record_count, expired.finding_count, expired.error_count) == (12, 10, 1)
    assert expired.error_summary == "agent_lost, file_errors:1"
    assert expired.duration_ms == 499_000


def test_heartbeat_resets_the_timeout():
    run = rs.heartbeat(running(), at(80))
    assert rs.expire(run, at(150), queue_timeout_s=120, heartbeat_timeout_s=90) is None


@pytest.mark.parametrize("status", ["completed", "partial", "failed"])
def test_terminal_runs_never_expire(status):
    run = dataclasses.replace(rs.new_run(T0), status=status)
    assert rs.expire(run, at(10_000), queue_timeout_s=1, heartbeat_timeout_s=1) is None


# ------------------------------------------------------------------ persistence mapping
def test_to_columns_and_from_row_round_trip():
    run = rs.finish(rs.request_cancel(running(), at(2)), at(9), Counts(records=4, findings=3, rejected=1, errors=2), AgentReport(
        outcome="finished", stop_reason="cancelled", coverage_started=True))
    columns = run.to_columns()
    assert columns["cancel_requested"] == 1 and isinstance(columns["cancel_requested"], int)
    assert rs.RunState.from_row(columns) == run


def test_purity_no_module_level_clock_or_io():
    import inspect
    source = inspect.getsource(rs)
    for forbidden in ("datetime.now", "datetime.utcnow", "time.time", "import sqlite3", "open(", "import os"):
        assert forbidden not in source, forbidden
