"""Pure timeout / lease / cancellation rules of the run state machine (2c-1). No database, no clock."""
import dataclasses
import datetime as dt

import pytest

from backend import run_state as rs
from backend.run_state import AgentReport, Counts, InvalidTransition, RunState, Timeouts, Verdict

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
TIMEOUTS = Timeouts(queue_s=120, heartbeat_s=90, finish_grace_s=5, cancel_grace_s=60)


def at(seconds):
    return T0 + dt.timedelta(seconds=seconds)


def running(heartbeat_at=10, **fields):
    """A run claimed at t=1s whose last sign of life was at `heartbeat_at`."""
    state = rs.start(rs.new_run(T0), at(1))
    if heartbeat_at != 1:
        state = rs.heartbeat(state, at(heartbeat_at))
    return dataclasses.replace(state, **fields)


# ------------------------------------------------------------------ Timeouts
def test_default_timeouts_are_the_approved_values():
    assert Timeouts() == Timeouts(queue_s=120.0, heartbeat_s=90.0, finish_grace_s=5.0, cancel_grace_s=60.0)


@pytest.mark.parametrize("kwargs", [dict(queue_s=0), dict(queue_s=-1), dict(heartbeat_s=0), dict(heartbeat_s=float("inf")),
                                    dict(queue_s=float("nan")), dict(heartbeat_s=True), dict(heartbeat_s="90"),
                                    dict(finish_grace_s=-1), dict(finish_grace_s=float("inf")), dict(finish_grace_s=None),
                                    dict(cancel_grace_s=-1), dict(cancel_grace_s=float("nan")), dict(cancel_grace_s="60")])
def test_invalid_timeouts_are_refused(kwargs):
    with pytest.raises(ValueError):
        Timeouts(**kwargs)


def test_zero_grace_and_disabled_cancel_grace_are_allowed():
    assert Timeouts(finish_grace_s=0).finish_grace_s == 0 and Timeouts(cancel_grace_s=None).cancel_grace_s is None


# ------------------------------------------------------------------ lease classification: fresh / overdue / lost
@pytest.mark.parametrize("age, expected", [
    (0, rs.FRESH), (89.999, rs.FRESH), (90.0, rs.FRESH),                    # at the heartbeat timeout: still fresh (inclusive)
    (90.001, rs.OVERDUE), (92.5, rs.OVERDUE), (94.999, rs.OVERDUE), (95.0, rs.OVERDUE),     # the finish window, inclusive
    (95.001, rs.LOST), (96, rs.LOST), (10_000, rs.LOST),
])
def test_lease_state_boundaries(age, expected):
    run = running(heartbeat_at=10)
    assert rs.lease_state(run, at(10 + age), TIMEOUTS) == expected


def test_a_heartbeat_resets_the_age():
    run = rs.heartbeat(running(heartbeat_at=10), at(100))
    assert rs.lease_state(run, at(100 + 90), TIMEOUTS) == rs.FRESH
    assert rs.lease_state(run, at(100 + 90.001), TIMEOUTS) == rs.OVERDUE
    assert rs.lease_state(run, at(100 + 95.001), TIMEOUTS) == rs.LOST


def test_without_a_heartbeat_the_age_runs_from_the_claim():
    run = running(heartbeat_at=1)
    assert run.last_heartbeat_at == run.started_at
    assert rs.lease_state(run, at(1 + 90), TIMEOUTS) == rs.FRESH
    assert rs.lease_state(dataclasses.replace(run, last_heartbeat_at=None), at(1 + 90.001), TIMEOUTS) == rs.OVERDUE


def test_zero_grace_has_no_overdue_window():
    exact = Timeouts(finish_grace_s=0)
    run = running(heartbeat_at=10)
    assert rs.lease_state(run, at(100), exact) == rs.FRESH
    assert rs.lease_state(run, at(100.001), exact) == rs.LOST


def test_a_request_timed_before_the_last_heartbeat_is_fresh():
    run = running(heartbeat_at=50)
    assert rs.lease_state(run, at(20), TIMEOUTS) == rs.FRESH                 # arrival time earlier than a committed heartbeat


def test_the_backend_start_floor_protects_healthy_agents_across_a_restart():
    run = running(heartbeat_at=10)
    restart = at(500)                                                        # the backend was down; agent heartbeats are old
    assert rs.lease_state(run, at(500 + 89), TIMEOUTS) == rs.LOST            # without the floor ...
    assert rs.lease_state(run, at(500 + 89), TIMEOUTS, not_before=restart) == rs.FRESH       # ... with it, a fresh start
    assert rs.lease_state(run, at(500 + 90.001), TIMEOUTS, not_before=restart) == rs.OVERDUE
    assert rs.lease_state(run, at(500 + 95.001), TIMEOUTS, not_before=restart) == rs.LOST


def test_a_floor_older_than_the_heartbeat_changes_nothing():
    run = running(heartbeat_at=300)
    assert rs.lease_state(run, at(300 + 90.001), TIMEOUTS, not_before=at(5)) == rs.OVERDUE


@pytest.mark.parametrize("status", ["queued", "completed", "partial", "failed"])
def test_only_running_runs_have_a_lease(status):
    with pytest.raises(InvalidTransition):
        rs.lease_state(dataclasses.replace(rs.new_run(T0), status=status), at(5), TIMEOUTS)


# ------------------------------------------------------------------ heartbeat is monotone
def test_heartbeat_never_moves_backwards():
    run = rs.heartbeat(running(heartbeat_at=10), at(50))
    earlier = rs.heartbeat(run, at(20))                                      # a request timed earlier committed later
    assert earlier.last_heartbeat_at == run.last_heartbeat_at == "2026-03-01T12:00:50.000Z"
    assert rs.heartbeat(run, at(50)).last_heartbeat_at == run.last_heartbeat_at
    assert rs.heartbeat(run, at(51)).last_heartbeat_at == "2026-03-01T12:00:51.000Z"


# ------------------------------------------------------------------ cancellation request
def test_the_first_cancel_request_is_stamped():
    run = rs.request_cancel(running(), at(30))
    assert run.cancel_requested and run.cancel_requested_at == "2026-03-01T12:00:30.000Z" and run.status == "running"


def test_a_repeated_cancel_request_changes_nothing():
    first = rs.request_cancel(running(), at(30))
    again = rs.request_cancel(first, at(45))
    assert again == first and again.cancel_requested_at == "2026-03-01T12:00:30.000Z"


def test_cancelling_a_queued_run_fails_it_and_stamps_nothing():
    cancelled = rs.request_cancel(rs.new_run(T0), at(3))
    assert cancelled.status == "failed" and cancelled.stop_reason == "cancelled" and cancelled.cancel_requested_at is None


@pytest.mark.parametrize("status", ["completed", "partial", "failed"])
def test_a_finished_run_cannot_be_cancelled(status):
    with pytest.raises(InvalidTransition):
        rs.request_cancel(dataclasses.replace(rs.new_run(T0), status=status), at(5))


def test_the_cancel_timestamp_round_trips_through_columns():
    run = rs.request_cancel(running(), at(30))
    columns = run.to_columns()
    assert columns["cancel_requested"] == 1 and columns["cancel_requested_at"] == "2026-03-01T12:00:30.000Z"
    assert RunState.from_row(columns) == run


# ------------------------------------------------------------------ expiry verdicts
@pytest.mark.parametrize("age, expected", [(0, None), (119.999, None), (120.0, None), (120.001, rs.QUEUE_TIMEOUT), (10_000, rs.QUEUE_TIMEOUT)])
def test_queued_runs_expire_after_the_queue_timeout(age, expected):
    verdict = rs.expiry_verdict(rs.new_run(T0), at(age), TIMEOUTS)
    assert (verdict.kind if verdict else None) == expected


def test_the_floor_also_protects_queued_runs_after_a_restart():
    queued = rs.new_run(T0)
    assert rs.expiry_verdict(queued, at(500), TIMEOUTS) == Verdict(rs.QUEUE_TIMEOUT)
    assert rs.expiry_verdict(queued, at(500 + 120), TIMEOUTS, not_before=at(500)) is None
    assert rs.expiry_verdict(queued, at(500 + 120.001), TIMEOUTS, not_before=at(500)) == Verdict(rs.QUEUE_TIMEOUT)


@pytest.mark.parametrize("age, expected", [(0, None), (90.001, None), (95.0, None), (95.001, rs.LOST)])
def test_running_runs_are_lost_only_after_the_finish_window(age, expected):
    verdict = rs.expiry_verdict(running(heartbeat_at=10), at(10 + age), TIMEOUTS)
    assert (verdict.kind if verdict else None) == expected


def test_the_overdue_window_is_not_an_expiry():
    """Between heartbeat_s and heartbeat_s + grace the run is still running: the agent may still finish."""
    assert rs.expiry_verdict(running(heartbeat_at=10), at(10 + 93), TIMEOUTS) is None


@pytest.mark.parametrize("status", ["completed", "partial", "failed"])
def test_finished_runs_never_expire(status):
    assert rs.expiry_verdict(dataclasses.replace(rs.new_run(T0), status=status), at(99_999), TIMEOUTS) is None


@pytest.mark.parametrize("wait, expected", [(0, None), (59.999, None), (60.0, None), (60.001, rs.CANCELLED)])
def test_an_unanswered_cancellation_is_enforced_after_the_grace(wait, expected):
    run = rs.heartbeat(rs.request_cancel(running(heartbeat_at=10), at(20)), at(20 + wait))      # the agent is alive, just ignoring it
    verdict = rs.expiry_verdict(run, at(20 + wait), TIMEOUTS)
    assert (verdict.kind if verdict else None) == expected
    if verdict:
        assert verdict.agent_lost is False


def test_a_cancelled_run_whose_agent_also_went_silent_is_marked_lost_too():
    run = rs.request_cancel(running(heartbeat_at=10), at(20))
    assert rs.expiry_verdict(run, at(10 + 95.001), TIMEOUTS) == Verdict(rs.CANCELLED, agent_lost=True)


def test_cancel_enforcement_can_be_disabled_and_needs_its_timestamp():
    run = rs.heartbeat(rs.request_cancel(running(heartbeat_at=10), at(20)), at(1000))
    assert rs.expiry_verdict(run, at(1000), Timeouts(cancel_grace_s=None)) is None
    legacy = dataclasses.replace(run, cancel_requested_at=None)
    assert rs.expiry_verdict(legacy, at(1000), TIMEOUTS) is None


def test_the_floor_applies_to_the_cancel_grace_as_well():
    run = rs.request_cancel(running(heartbeat_at=10), at(20))
    restart = at(500)
    assert rs.expiry_verdict(rs.heartbeat(run, at(520)), at(560), TIMEOUTS, not_before=restart) is None
    assert rs.expiry_verdict(rs.heartbeat(run, at(561)), at(561), TIMEOUTS, not_before=restart) == Verdict(rs.CANCELLED)


def test_lost_without_a_cancel_request_is_plain_lost():
    assert rs.expiry_verdict(running(heartbeat_at=10), at(200), TIMEOUTS) == Verdict(rs.LOST)


# ------------------------------------------------------------------ the cancelled outcome
def test_cancelled_is_partial_even_when_nothing_was_stored():
    assert rs.decide_outcome(Counts(), AgentReport(outcome="cancelled")) == ("partial", ("stopped_cancelled",))
    assert rs.decide_outcome(Counts(records=5), AgentReport(outcome="cancelled")) == ("partial", ("stopped_cancelled",))


def test_cancelled_reports_a_silent_agent_and_other_gaps_in_order():
    report = AgentReport(outcome="cancelled", agent_lost=True, roots_not_scanned=1, seq_conflicts=2)
    assert rs.decide_outcome(Counts(records=5, errors=3, rejected=1), report) == (
        "partial", ("stopped_cancelled", "agent_lost", "roots_not_scanned:1", "file_errors:3", "records_rejected:1", "seq_conflicts:2"))


def test_cancelled_with_every_record_rejected_is_failed():
    assert rs.decide_outcome(Counts(records=0, rejected=4), AgentReport(outcome="cancelled"))[0] == "failed"


def test_finishing_a_cancelled_run_records_cancelled_as_the_stop_reason():
    run = rs.request_cancel(running(), at(20))
    done = rs.finish(run, at(40), Counts(records=3, findings=3), AgentReport(outcome="cancelled"))
    assert (done.status, done.stop_reason, done.error_summary) == ("partial", "cancelled", "stopped_cancelled")
    assert done.cancel_requested and done.cancel_requested_at == run.cancel_requested_at and done.duration_ms == 39_000


def test_the_agent_can_still_end_a_cancelled_run_itself():
    run = rs.request_cancel(running(), at(20))
    done = rs.finish(run, at(30), Counts(records=3), AgentReport(outcome="finished", stop_reason="cancelled", coverage_started=True))
    assert (done.status, done.stop_reason, done.error_summary) == ("partial", "cancelled", "stopped_cancelled")


def test_agent_lost_must_be_a_boolean():
    for bad in (1, "yes", None):
        with pytest.raises(ValueError):
            AgentReport(outcome="cancelled", agent_lost=bad)
    assert "cancelled" in rs.OUTCOMES and rs.OUTCOMES[:3] == ("finished", "failed", "lost")


# ------------------------------------------------------------------ expire() keeps its contract and gains the new cases
def test_expire_keeps_its_original_behaviour_with_the_original_arguments():
    kwargs = dict(queue_timeout_s=120, heartbeat_timeout_s=90)
    queued = rs.new_run(T0)
    assert rs.expire(queued, at(120), **kwargs) is None
    assert rs.expire(queued, at(120.001), **kwargs).error_summary == "agent_not_connected"
    run = running(heartbeat_at=10)
    assert rs.expire(run, at(100), **kwargs) is None
    lost = rs.expire(run, at(100.001), **kwargs)
    assert lost.status == "failed" and lost.error_summary == "no_usable_data, agent_lost"
    with_data = rs.update_counts(run, Counts(records=4, findings=4))
    partial = rs.expire(with_data, at(100.001), **kwargs)
    assert partial.status == "partial" and partial.stop_reason == "agent_lost" and partial.record_count == 4


def test_expire_honours_the_finish_window():
    kwargs = dict(queue_timeout_s=120, heartbeat_timeout_s=90, finish_grace_s=5)
    run = rs.update_counts(running(heartbeat_at=10), Counts(records=2, findings=2))
    assert rs.expire(run, at(10 + 95), **kwargs) is None
    assert rs.expire(run, at(10 + 95.001), **kwargs).status == "partial"


def test_expire_ends_an_unanswered_cancellation_as_partial_cancelled():
    kwargs = dict(queue_timeout_s=120, heartbeat_timeout_s=90, cancel_grace_s=60)
    run = rs.update_counts(rs.request_cancel(running(heartbeat_at=10), at(20)), Counts(records=2, findings=2))
    alive = rs.heartbeat(run, at(80.5))
    ended = rs.expire(alive, at(80.5), **kwargs)
    assert (ended.status, ended.stop_reason, ended.error_summary) == ("partial", "cancelled", "stopped_cancelled")
    assert ended.record_count == 2 and ended.cancel_requested_at == run.cancel_requested_at
    silent = rs.expire(run, at(10 + 90.001), **kwargs)
    assert silent.error_summary == "stopped_cancelled, agent_lost" and silent.status == "partial"


def test_expire_of_a_cancelled_run_with_no_data_is_partial_not_failed():
    run = rs.request_cancel(running(heartbeat_at=10), at(20))
    ended = rs.expire(run, at(300), queue_timeout_s=120, heartbeat_timeout_s=90)
    assert ended.status == "partial" and ended.record_count == 0 and ended.stop_reason == "cancelled"


def test_expire_without_cancel_grace_leaves_a_live_cancelled_run_alone():
    run = rs.heartbeat(rs.request_cancel(running(heartbeat_at=10), at(20)), at(1000))
    assert rs.expire(run, at(1000), queue_timeout_s=120, heartbeat_timeout_s=90) is None


def test_expire_with_a_floor():
    run = running(heartbeat_at=10)
    kwargs = dict(queue_timeout_s=120, heartbeat_timeout_s=90, not_before=at(500))
    assert rs.expire(run, at(560), **kwargs) is None
    assert rs.expire(run, at(500 + 90.001), **kwargs).status == "failed"


# ------------------------------------------------------------------ cancellation is partial on every path (nothing stored too)
def cooperative(**fields):
    base = dict(outcome="finished", stop_reason="cancelled", cancel_requested=True)
    base.update(fields)
    return AgentReport(**base)


def test_cancelled_on_request_truth_table():
    assert rs.cancelled_on_request(AgentReport(outcome="cancelled"))                                  # enforced by the backend
    assert rs.cancelled_on_request(cooperative())                                                     # the agent stopped on request
    assert not rs.cancelled_on_request(cooperative(cancel_requested=False))                           # its say-so alone is not enough
    assert not rs.cancelled_on_request(cooperative(stop_reason="completed"))
    assert not rs.cancelled_on_request(cooperative(stop_reason="time_limit"))
    assert not rs.cancelled_on_request(AgentReport(outcome="failed", stop_reason="cancelled", cancel_requested=True))
    assert not rs.cancelled_on_request(AgentReport(outcome="lost", cancel_requested=True))


def test_cooperative_cancellation_with_nothing_stored_is_partial():
    assert rs.decide_outcome(Counts(), cooperative()) == ("partial", ("stopped_cancelled",))
    assert rs.decide_outcome(Counts(), cooperative(roots_not_scanned=1)) == ("partial", ("stopped_cancelled", "roots_not_scanned:1"))


def test_cooperative_and_enforced_cancellation_agree():
    for counts in (Counts(), Counts(records=4, findings=4), Counts(records=4, errors=2)):
        enforced = rs.decide_outcome(counts, AgentReport(outcome="cancelled"))
        assert rs.decide_outcome(counts, cooperative()) == enforced and enforced[0] == "partial"


def test_cooperative_cancellation_after_observations_is_partial():
    assert rs.decide_outcome(Counts(records=3, findings=3), cooperative(coverage_started=True)) == ("partial", ("stopped_cancelled",))


def test_an_agent_cannot_turn_a_failure_into_partial_by_calling_it_cancelled():
    """No cancel request on record: the claim is just another stop reason, and with nothing stored the run has failed."""
    claim_only = cooperative(cancel_requested=False)
    status, reasons = rs.decide_outcome(Counts(), claim_only)
    assert status == "failed" and reasons[0] == "no_usable_data"
    assert rs.decide_outcome(Counts(records=2), claim_only)[0] == "partial"                           # with data it is a stopped scan


def test_ordinary_failures_stay_failed_even_after_a_cancel_request():
    assert rs.decide_outcome(Counts(), AgentReport(outcome="failed", stop_reason="cancelled", cancel_requested=True,
                                                   fatal_code="scan_crashed")) == ("failed", ("scan_crashed",))
    assert rs.decide_outcome(Counts(records=5), AgentReport(outcome="failed", cancel_requested=True))[0] == "failed"


def test_a_lost_agent_with_no_data_is_still_failed_unless_the_backend_cancelled_it():
    assert rs.decide_outcome(Counts(), AgentReport(outcome="lost", cancel_requested=True))[0] == "failed"
    assert rs.decide_outcome(Counts(), AgentReport(outcome="cancelled", agent_lost=True))[0] == "partial"


def test_a_cancelled_run_whose_every_record_was_rejected_has_no_usable_data():
    assert rs.decide_outcome(Counts(rejected=3), cooperative())[0] == "failed"
    assert rs.decide_outcome(Counts(rejected=3), AgentReport(outcome="cancelled"))[0] == "failed"


def test_cancel_requested_must_be_a_boolean():
    for bad in (1, "yes", None):
        with pytest.raises(ValueError):
            AgentReport(outcome="finished", cancel_requested=bad)
    assert AgentReport(outcome="finished").cancel_requested is False


def test_finishing_a_cooperatively_cancelled_run_with_nothing_stored():
    run = rs.request_cancel(running(), at(20))
    done = rs.finish(run, at(30), Counts(), cooperative())
    assert (done.status, done.stop_reason, done.error_summary) == ("partial", "cancelled", "stopped_cancelled")
