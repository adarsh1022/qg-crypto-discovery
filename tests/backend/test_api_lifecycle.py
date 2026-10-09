"""HTTP API lifecycle: lease timing, the finish window, queue timeout, the sweeper, cancellation, restart recovery.
Time is the test's: nothing sleeps."""
import pytest

from apifx import START, FakeClock, make_api
from backend import service
from backend.api_models import RunView
from backend.app import sweep_once
from ingestfx import ok_record, summary


def error_of(response):
    return response.json()["error"]


def running_with_data(api, records=1, **create):
    run = api.create(**create)
    agent = api.agent()
    assert agent.claim(run["run_id"]).status_code == 200
    if records:
        assert agent.upload([[i, ok_record(rf"C:\app\{i}.pem", n=i + 1)] for i in range(records)]).status_code == 200
    return run["run_id"], agent


def clean_summary(records=1):
    return summary(records)


def view_after(api, run_id):
    return api.get(run_id)


def test_the_public_run_view_matches_its_declared_fields():
    assert set(RunView.model_fields) == set(service.RUN_VIEW_FIELDS)


# =========================================================================== the lease timeline: fresh / overdue / lost
FRESH = [0, 30, 89.999, 90.0]
OVERDUE = [90.001, 92.5, 94.999, 95.0]
LOST = [95.001, 96, 500]


@pytest.mark.parametrize("age", FRESH)
def test_a_fresh_lease_accepts_everything(api, age):
    for operation in ("heartbeat", "upload", "finish"):
        run_id, agent = running_with_data(api)
        api.clock.advance(age)
        if operation == "heartbeat":
            assert agent.heartbeat().status_code == 200
        elif operation == "upload":
            assert agent.upload([[5, ok_record(r"C:\app\x.pem", n=7)]]).status_code == 200
        else:
            assert agent.finish(summary=clean_summary()).json()["run"]["status"] == "completed"
        api.clock.set(START)


@pytest.mark.parametrize("age", OVERDUE)
def test_in_the_overdue_window_only_finish_is_accepted(api, age):
    run_id, agent = running_with_data(api)
    api.clock.advance(age)
    for refused in (agent.heartbeat(), agent.upload([[5, ok_record(r"C:\app\x.pem", n=7)]])):
        assert refused.status_code == 409 and error_of(refused)["code"] == "lease_overdue"
        assert error_of(refused)["details"]["status"] == "running"
    assert api.get(run_id)["status"] == "running" and api.get(run_id)["record_count"] == 1       # nothing changed
    finish = agent.finish(summary=clean_summary())
    assert finish.status_code == 200 and finish.json()["run"]["status"] == "completed"


@pytest.mark.parametrize("age", LOST)
def test_a_lost_lease_ends_the_run_and_refuses_everything(api, age):
    for operation in ("heartbeat", "upload", "finish"):
        run_id, agent = running_with_data(api)
        api.clock.advance(age)
        response = {"heartbeat": agent.heartbeat, "upload": lambda: agent.upload([[5, ok_record(r"C:\app\x.pem", n=7)]]),
                    "finish": lambda: agent.finish(summary=clean_summary())}[operation]()
        expected = "run_already_finished" if operation == "finish" else "run_not_running"
        assert response.status_code == 409 and error_of(response)["code"] == expected, (operation, age)
        assert error_of(response)["details"]["status"] == "partial"
        run = api.get(run_id)                                                   # the expiry committed although the call was refused
        assert (run["status"], run["stop_reason"], run["error_summary"], run["record_count"]) == ("partial", "agent_lost", "agent_lost", 1)
        assert run["finished_at"] is not None
        api.clock.set(START)


def test_a_lost_run_with_no_data_is_failed(api):
    run_id, agent = running_with_data(api, records=0)
    api.clock.advance(96)
    assert agent.heartbeat().status_code == 409
    run = api.get(run_id)
    assert (run["status"], run["error_summary"]) == ("failed", "no_usable_data, agent_lost")


def test_the_timeline_is_measured_from_the_last_sign_of_life(api):
    run_id, agent = running_with_data(api)
    api.clock.advance(80)
    assert agent.heartbeat().status_code == 200
    api.clock.advance(89.999)
    assert agent.heartbeat().status_code == 200
    api.clock.advance(95.0)
    assert agent.finish(summary=clean_summary()).status_code == 200


def test_the_finish_window_is_the_only_extension(api):
    """After a refused (overdue) heartbeat the lease is NOT renewed: the run still dies at heartbeat timeout + grace."""
    run_id, agent = running_with_data(api)
    api.clock.advance(92)
    assert agent.heartbeat().status_code == 409
    api.clock.advance(3.001)
    assert agent.finish(summary=clean_summary()).status_code == 409 and api.get(run_id)["status"] == "partial"


def test_a_reconnecting_agent_learns_how_the_run_ended(api):
    run_id, agent = running_with_data(api)
    api.clock.advance(200)
    response = agent.finish(summary=clean_summary())
    final = error_of(response)["details"]["run"]
    assert final["status"] == "partial" and final["stop_reason"] == "agent_lost" and final == api.get(run_id)


class WatchedClock(FakeClock):
    """A clock that tells the test when the application has read it (i.e. when a request has arrived)."""

    def __init__(self):
        super().__init__()
        self.reads = 0

    def __call__(self):
        self.reads += 1
        return super().__call__()


def test_a_request_is_judged_at_its_arrival_time_even_if_it_waits_for_the_write_lock(tmp_path):
    """The deadline is measured when the request ARRIVES: time that passes while it queues behind a writer is not held against it."""
    import threading
    import time
    from backend import db
    clock = WatchedClock()
    api = make_api(tmp_path, clock=clock)
    run_id, agent = running_with_data(api)
    clock.advance(80)                                                                   # 10 s left before the heartbeat deadline
    holder = db.connect(api.db_path)
    holder.execute("BEGIN IMMEDIATE")                                                   # another writer holds the database
    outcome = {}
    arrived = clock.reads
    worker = threading.Thread(target=lambda: outcome.setdefault("response", agent.heartbeat()))
    worker.start()
    while clock.reads == arrived:                                                       # wait until the app has read the clock
        time.sleep(0.005)
    time.sleep(0.05)
    clock.advance(100)                                                                  # ... and let a lot of time pass in the queue
    holder.execute("ROLLBACK")
    holder.close()
    worker.join(30)
    assert outcome["response"].status_code == 200 and outcome["response"].json()["status"] == "running"
    assert api.get(run_id)["last_heartbeat_at"] == "2026-03-01T12:01:20.000Z"           # stamped with the arrival time (T+80)


# =========================================================================== queue timeout
@pytest.mark.parametrize("age", [0, 60, 119.999, 120.0])
def test_a_queued_run_can_be_claimed_until_the_queue_timeout(api, age):
    run = api.create()
    api.clock.advance(age)
    assert api.agent().claim(run["run_id"]).status_code == 200


@pytest.mark.parametrize("age", [120.001, 121, 10_000])
def test_a_queued_run_that_waited_too_long_fails_instead_of_being_claimed(api, age):
    run = api.create()
    api.clock.advance(age)
    response = api.agent().claim(run["run_id"])
    assert response.status_code == 409 and error_of(response)["code"] == "run_not_claimable"
    stored = api.get(run["run_id"])
    assert (stored["status"], stored["stop_reason"], stored["error_summary"]) == ("failed", "agent_not_connected", "agent_not_connected")
    assert stored["started_at"] is None and stored["host_id"] is None


# =========================================================================== the sweeper
def test_the_sweeper_expires_stale_runs_and_is_idempotent(api):
    queued = api.create()
    running_id, agent = running_with_data(api)
    api.clock.advance(94)
    assert sweep_once(api.app) == 0                                                  # nothing is overdue-lost yet
    api.clock.advance(1.001)
    assert sweep_once(api.app) == 1 and api.get(running_id)["status"] == "partial"
    assert api.get(queued["run_id"])["status"] == "queued"
    api.clock.advance(25)
    assert sweep_once(api.app) == 1 and api.get(queued["run_id"])["status"] == "failed"
    assert sweep_once(api.app) == 0


def test_the_sweeper_leaves_healthy_and_finished_runs_alone(api):
    healthy_id, healthy = running_with_data(api)
    done_id, done = running_with_data(api)
    done.finish(summary=clean_summary())
    for _ in range(5):
        api.clock.advance(60)
        assert healthy.heartbeat().status_code == 200
        assert sweep_once(api.app) == 0
    assert api.get(healthy_id)["status"] == "running" and api.get(done_id)["status"] == "completed"


def test_reads_do_not_expire_anything(api):
    run_id, agent = running_with_data(api)
    api.clock.advance(1000)
    assert api.get(run_id)["status"] == "running" and api.client.get("/api/runs").json()["runs"][0]["status"] == "running"


def test_the_sweeper_task_runs_with_the_application(tmp_path):
    from fastapi.testclient import TestClient
    import time
    from apifx import BASE_URL
    api = make_api(tmp_path, sweep_interval_s=0.05)
    run = api.create()
    api.clock.advance(500)
    with TestClient(api.app, base_url=BASE_URL) as client:                       # entering the context starts the lifespan
        for _ in range(100):
            if client.get(f"/api/runs/{run['run_id']}").json()["run"]["status"] == "failed":
                break
            time.sleep(0.05)
        assert client.get(f"/api/runs/{run['run_id']}").json()["run"]["error_summary"] == "agent_not_connected"


# =========================================================================== cancellation
def test_cancelling_a_queued_run_fails_it_as_cancelled(api):
    run = api.create()
    response = api.cancel(run["run_id"])
    cancelled = response.json()["run"]
    assert response.status_code == 200 and cancelled["status"] == "failed" and cancelled["stop_reason"] == "cancelled"
    assert cancelled["error_summary"] == "cancelled" and cancelled["started_at"] is None
    assert api.agent().claim(run["run_id"]).status_code == 409


def test_cancelling_is_idempotent_for_a_queued_run(api):
    run = api.create()
    first = api.cancel(run["run_id"]).json()
    api.clock.advance(10)
    second = api.cancel(run["run_id"])
    assert second.status_code == 200 and second.json() == first


def test_cancelling_a_running_run_only_asks_it_to_stop(api):
    run_id, agent = running_with_data(api)
    api.clock.advance(10)
    response = api.cancel(run_id)
    run = response.json()["run"]
    assert response.status_code == 200 and run["status"] == "running" and run["cancel_requested"] is True
    assert run["cancel_requested_at"] == "2026-03-01T12:00:10.000Z" and run["finished_at"] is None


def test_a_repeated_cancel_keeps_the_first_timestamp(api):
    run_id, agent = running_with_data(api)
    api.clock.advance(10)
    first = api.cancel(run_id).json()["run"]
    api.clock.advance(30)
    second = api.cancel(run_id)
    assert second.status_code == 200 and second.json()["run"]["cancel_requested_at"] == first["cancel_requested_at"]
    assert second.json()["run"] == first


def test_cancelling_needs_no_lease(api):
    run_id, agent = running_with_data(api)
    from apifx import TOKEN_HEADER
    for headers in ({}, {TOKEN_HEADER: "0" * 32}, {TOKEN_HEADER: agent.token}):
        assert api.client.post(f"/api/runs/{run_id}/cancel", headers=headers).status_code == 200


def test_the_agent_observes_the_cancellation_and_ends_the_run_as_partial(api):
    run_id, agent = running_with_data(api, records=2)
    api.cancel(run_id)
    assert agent.heartbeat().json()["cancel_requested"] is True
    in_flight = agent.upload([[2, ok_record(r"C:\app\late.pem", n=9)]])              # work already under way is still accepted
    assert in_flight.status_code == 200 and in_flight.json()["cancel_requested"] is True
    final = agent.finish(summary=summary(3, stop_reason="cancelled", roots=(("C:\\app", "partial"),)))
    run = final.json()["run"]
    assert final.status_code == 200 and run["status"] == "partial" and run["stop_reason"] == "cancelled"
    assert run["error_summary"] == "stopped_cancelled" and run["record_count"] == 3 and run["cancel_requested"] is True


def test_cancel_after_the_run_ended_as_cancelled_is_idempotent(api):
    run_id, agent = running_with_data(api)
    api.cancel(run_id)
    final = agent.finish(summary=summary(1, stop_reason="cancelled", roots=(("C:\\app", "partial"),))).json()["run"]
    again = api.cancel(run_id)
    assert again.status_code == 200 and again.json()["run"] == final


def test_a_cancel_that_arrives_too_late_does_not_rewrite_a_clean_finish(api):
    run_id, agent = running_with_data(api)
    api.cancel(run_id)
    run = agent.finish(summary=clean_summary()).json()["run"]
    assert run["status"] == "completed" and run["cancel_requested"] is True


def test_cancelling_a_finished_run_is_refused(api):
    run_id, agent = running_with_data(api)
    agent.finish(summary=clean_summary())
    response = api.cancel(run_id)
    assert response.status_code == 409 and error_of(response)["code"] == "run_not_cancellable"
    assert error_of(response)["details"]["status"] == "completed"
    failed_id, failed = running_with_data(api)
    failed.finish(outcome="failed", fatal_code="boom")
    assert api.cancel(failed_id).status_code == 409


def test_cancelling_an_unknown_run(api):
    response = api.cancel("0" * 32)
    assert response.status_code == 404 and error_of(response)["code"] == "run_not_found"


# ---- cancellation the agent does not answer
@pytest.mark.parametrize("wait, ended", [(59.999, False), (60.0, False), (60.001, True)])
def test_an_unanswered_cancellation_is_enforced_after_the_grace(api, wait, ended):
    run_id, agent = running_with_data(api, records=2)
    api.clock.advance(5)
    api.cancel(run_id)
    for _ in range(int(wait // 30)):                                               # the agent keeps heartbeating but ignores it
        api.clock.advance(30)
        assert agent.heartbeat().status_code == 200
    api.clock.advance(wait - 30 * int(wait // 30))
    response = agent.heartbeat()
    run = api.get(run_id)
    if ended:
        assert response.status_code == 409 and error_of(response)["code"] == "run_not_running"
        assert (run["status"], run["stop_reason"], run["error_summary"]) == ("partial", "cancelled", "stopped_cancelled")
        assert run["record_count"] == 2 and run["agent_summary"] is None
    else:
        assert response.status_code == 200 and run["status"] == "running"


def test_a_cancelled_and_silent_agent_is_reported_as_lost_too(api):
    run_id, agent = running_with_data(api)
    api.cancel(run_id)
    api.clock.advance(95.001)
    assert sweep_once(api.app) == 1
    run = api.get(run_id)
    assert (run["status"], run["stop_reason"], run["error_summary"]) == ("partial", "cancelled", "stopped_cancelled, agent_lost")


def test_enforced_cancellation_with_nothing_stored_is_still_partial(api):
    run_id, agent = running_with_data(api, records=0)
    api.cancel(run_id)
    api.clock.advance(61)
    assert sweep_once(api.app) == 1 and api.get(run_id)["status"] == "partial"
    assert api.cancel(run_id).status_code == 200


def test_finish_after_enforced_cancellation_carries_the_final_view(api):
    run_id, agent = running_with_data(api)
    api.cancel(run_id)
    api.clock.advance(61)
    late = agent.finish(summary=clean_summary())
    assert late.status_code == 409 and error_of(late)["code"] == "run_already_finished"
    assert error_of(late)["details"]["run"]["stop_reason"] == "cancelled"


# ---- races between cancel, finish, claim and timeouts (all serialised; the order decides)
def test_cancel_then_finish_and_finish_then_cancel_are_both_consistent(api):
    first_id, first = running_with_data(api)
    api.cancel(first_id)
    assert first.finish(summary=clean_summary()).status_code == 200
    second_id, second = running_with_data(api)
    assert second.finish(summary=clean_summary()).status_code == 200
    assert api.cancel(second_id).status_code == 409
    assert api.get(first_id)["cancel_requested"] is True and api.get(second_id)["cancel_requested"] is False


def test_cancel_and_claim_race_in_both_orders(api):
    first, second = api.create(), api.create()
    api.cancel(first["run_id"])
    assert api.agent().claim(first["run_id"]).status_code == 409
    assert api.agent().claim(second["run_id"]).status_code == 200
    cancel = api.cancel(second["run_id"])
    assert cancel.status_code == 200 and cancel.json()["run"]["status"] == "running"


def test_cancel_and_queue_timeout_race_at_the_boundary(api):
    exactly, past = api.create(), api.create()
    api.clock.advance(120.0)
    assert api.cancel(exactly["run_id"]).json()["run"]["stop_reason"] == "cancelled"        # still queued: cancelled
    api.clock.advance(0.001)
    response = api.cancel(past["run_id"])
    assert response.status_code == 409 and error_of(response)["details"]["stop_reason"] == "agent_not_connected"


def test_cancel_and_lost_heartbeat_race_at_the_boundary(api):
    run_id, agent = running_with_data(api)
    api.clock.advance(95.0)
    assert api.cancel(run_id).json()["run"]["status"] == "running"                       # the window is still open
    api.clock.advance(0.001)
    assert api.cancel(run_id).json()["run"]["status"] == "partial"                       # expired first; cancel is then a repeat
    assert api.get(run_id)["stop_reason"] == "cancelled"


# =========================================================================== restart recovery
def test_a_restart_gives_running_runs_a_fresh_window_and_leases_survive(tmp_path):
    clock = FakeClock()
    first = make_api(tmp_path, clock=clock)
    run_id, agent = running_with_data(first)
    clock.advance(500)                                                               # the backend was down for 500 s
    second = make_api(tmp_path, clock=clock)                                         # a new process on the same database
    clock.advance(10)
    revived = second.client.post(f"/api/runs/{run_id}/heartbeat", headers=agent.headers())
    assert revived.status_code == 200 and second.get(run_id)["status"] == "running"      # the old token still works
    assert second.client.post(f"/api/runs/{run_id}/heartbeat", headers={"X-Run-Token": "0" * 32}).status_code == 403


def test_without_a_sign_of_life_after_a_restart_the_run_is_still_lost(tmp_path):
    clock = FakeClock()
    first = make_api(tmp_path, clock=clock)
    run_id, agent = running_with_data(first)
    clock.advance(500)
    second = make_api(tmp_path, clock=clock)
    clock.advance(95.0)
    assert sweep_once(second.app) == 0
    clock.advance(0.001)
    assert sweep_once(second.app) == 1 and second.get(run_id)["status"] == "partial"


def test_queued_runs_survive_a_restart_and_can_still_be_claimed(tmp_path):
    clock = FakeClock()
    first = make_api(tmp_path, clock=clock)
    run = first.create()
    clock.advance(1000)
    second = make_api(tmp_path, clock=clock)
    clock.advance(30)
    assert second.agent().claim(run["run_id"]).status_code == 200


def test_a_queued_run_still_times_out_after_a_restart(tmp_path):
    clock = FakeClock()
    first = make_api(tmp_path, clock=clock)
    run = first.create()
    clock.advance(1000)
    second = make_api(tmp_path, clock=clock)
    clock.advance(120.001)
    assert second.agent().claim(run["run_id"]).status_code == 409 and second.get(run["run_id"])["status"] == "failed"


def test_finished_runs_are_untouched_by_a_restart_and_a_sweep(tmp_path):
    clock = FakeClock()
    first = make_api(tmp_path, clock=clock)
    run_id, agent = running_with_data(first)
    final = agent.finish(summary=clean_summary()).json()["run"]
    clock.advance(10_000)
    second = make_api(tmp_path, clock=clock)
    assert sweep_once(second.app) == 0 and second.get(run_id) == final


def test_an_unanswered_cancellation_gets_a_fresh_grace_after_a_restart(tmp_path):
    clock = FakeClock()
    first = make_api(tmp_path, clock=clock)
    run_id, agent = running_with_data(first)
    first.cancel(run_id)
    clock.advance(500)
    second = make_api(tmp_path, clock=clock)
    clock.advance(30)
    assert second.client.post(f"/api/runs/{run_id}/heartbeat", headers=agent.headers()).json()["cancel_requested"] is True
    clock.advance(30)
    assert second.client.post(f"/api/runs/{run_id}/heartbeat", headers=agent.headers()).status_code == 200
    clock.advance(0.001)
    assert second.client.post(f"/api/runs/{run_id}/heartbeat", headers=agent.headers()).status_code == 409
    assert second.get(run_id)["status"] == "partial" and second.get(run_id)["stop_reason"] == "cancelled"


# ---- cancellation ends partial on every path, including when nothing was stored
def test_cooperative_cancellation_before_any_observation_is_partial(api):
    run_id, agent = running_with_data(api, records=0)
    api.cancel(run_id)
    assert agent.heartbeat().json()["cancel_requested"] is True
    run = agent.finish(summary=summary(0, stop_reason="cancelled", roots=(("C:\\app", "not_reached"),))).json()["run"]
    assert (run["status"], run["stop_reason"], run["record_count"]) == ("partial", "cancelled", 0)
    assert run["error_summary"] == "stopped_cancelled, roots_not_scanned:1"


def test_cooperative_cancellation_after_observations_ends_partial(api):
    run_id, agent = running_with_data(api, records=3)
    api.cancel(run_id)
    run = agent.finish(summary=summary(3, stop_reason="cancelled", roots=(("C:\\app", "partial"),))).json()["run"]
    assert (run["status"], run["stop_reason"], run["record_count"], run["error_summary"]) == ("partial", "cancelled", 3, "stopped_cancelled")


def test_forced_cancellation_before_any_observation_is_partial(api):
    run_id, agent = running_with_data(api, records=0)
    api.cancel(run_id)
    api.clock.advance(60.001)
    assert agent.heartbeat().status_code == 409
    run = api.get(run_id)
    assert (run["status"], run["stop_reason"], run["record_count"], run["error_summary"]) == ("partial", "cancelled", 0, "stopped_cancelled")


def test_an_agent_failure_during_cancellation_is_still_a_failure(api):
    run_id, agent = running_with_data(api, records=0)
    api.cancel(run_id)
    run = agent.finish(outcome="failed", fatal_code="scan_crashed").json()["run"]
    assert (run["status"], run["error_summary"]) == ("failed", "scan_crashed")


def test_claiming_to_be_cancelled_without_a_cancel_request_does_not_rescue_a_failed_scan(api):
    run_id, agent = running_with_data(api, records=0)
    run = agent.finish(summary=summary(0, stop_reason="cancelled", roots=(("C:\\app", "not_reached"),))).json()["run"]
    assert run["status"] == "failed" and run["error_summary"].startswith("no_usable_data") and run["cancel_requested"] is False


def test_a_run_with_no_cancellation_and_no_data_still_fails_as_before(api):
    run_id, agent = running_with_data(api, records=0)
    api.clock.advance(96)
    assert agent.heartbeat().status_code == 409
    assert api.get(run_id)["status"] == "failed" and api.get(run_id)["error_summary"] == "no_usable_data, agent_lost"
