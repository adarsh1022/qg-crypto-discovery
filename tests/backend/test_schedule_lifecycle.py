"""The scheduler task inside the application: it starts and stops with the lifespan, never runs twice, survives errors, and
several application instances on one database still create one run per due occurrence.

These tests use the real lifespan (TestClient as a context manager) with a short tick, and the fake clock for 'now'."""
import contextlib
import time

import pytest
from fastapi.testclient import TestClient

from apifx import BASE_URL, make_api
from backend import app as app_module, db, schedules
from backend.settings import Settings

FS = {"run_type": "filesystem", "interval_seconds": 15, "config": {"roots": ["C:\\certs"]}}


def wait_for(predicate, seconds=10.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def runs_in(path):
    with contextlib.closing(db.connect(path)) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM runs ORDER BY run_number")]


# =========================================================================== settings
def test_the_default_tick_is_five_seconds_and_the_scheduler_can_be_switched_off(tmp_path):
    assert Settings(db_path=tmp_path / "a.db").schedule_tick_s == 5.0
    assert Settings(db_path=tmp_path / "a.db", schedule_tick_s=None).schedule_tick_s is None
    assert Settings(db_path=tmp_path / "a.db", schedule_tick_s=1).schedule_tick_s == 1


@pytest.mark.parametrize("value", [0, -1, True, False, "5", float("inf"), float("nan"), [5]])
def test_a_bad_tick_setting_is_refused(tmp_path, value):
    with pytest.raises(ValueError, match="schedule_tick_s"):
        Settings(db_path=tmp_path / "a.db", schedule_tick_s=value)


# =========================================================================== start and stop
def test_the_scheduler_task_starts_with_the_application_and_is_gone_when_it_stops(tmp_path):
    api = make_api(tmp_path, schedule_tick_s=0.05)
    assert api.app.state.scheduler_task is None
    with TestClient(api.app, base_url=BASE_URL):
        task = api.app.state.scheduler_task
        assert task is not None and not task.done()
    assert task.done() and task.cancelled() and api.app.state.scheduler_task is None


def test_no_scheduler_task_exists_when_the_tick_is_switched_off(tmp_path):
    api = make_api(tmp_path, schedule_tick_s=None)
    with TestClient(api.app, base_url=BASE_URL):
        assert api.app.state.scheduler_task is None


def test_entering_the_lifespan_again_while_it_runs_does_not_start_a_second_loop(tmp_path, monkeypatch):
    started = []
    real = app_module._schedule_loop

    async def counting(app, interval):
        started.append(interval)
        await real(app, interval)
    monkeypatch.setattr(app_module, "_schedule_loop", counting)
    api = make_api(tmp_path, schedule_tick_s=0.05)
    with TestClient(api.app, base_url=BASE_URL):
        first = api.app.state.scheduler_task
        with TestClient(api.app, base_url=BASE_URL):
            assert api.app.state.scheduler_task is first
            assert wait_for(lambda: len(started) >= 1)
        assert not first.done()                                            # the inner exit did not stop the outer one's loop
    assert started == [0.05]                                                # one loop in total
    assert first.done() and api.app.state.scheduler_task is None


def test_the_application_can_be_started_and_stopped_repeatedly(tmp_path):
    api = make_api(tmp_path, schedule_tick_s=0.05)
    seen = []
    for _ in range(3):
        with TestClient(api.app, base_url=BASE_URL):
            seen.append(api.app.state.scheduler_task)
            assert not seen[-1].done()
        assert seen[-1].done()
    assert len({id(t) for t in seen}) == 3


def test_stopping_the_application_while_a_tick_is_running_neither_hangs_nor_loses_the_transaction(tmp_path, monkeypatch):
    api = make_api(tmp_path, schedule_tick_s=0.01)
    real = schedules.tick
    entered = []

    def slow(conn, ctx, now):
        entered.append(1)
        time.sleep(0.3)
        return real(conn, ctx, now)
    monkeypatch.setattr(schedules, "tick", slow)
    with contextlib.closing(db.connect(api.db_path)) as conn:
        schedules.create_schedule(conn, api.clock(), run_type="filesystem", interval_seconds=15, config={"roots": ["C:\\c"]})
    api.clock.advance(15)
    started = time.monotonic()
    with TestClient(api.app, base_url=BASE_URL):
        assert wait_for(lambda: entered)
    assert time.monotonic() - started < 10                                  # stopping did not hang
    assert len(runs_in(api.db_path)) <= 1                                   # whatever happened, nothing was half-created


# =========================================================================== running
def test_a_due_schedule_creates_its_run_in_the_background_without_any_request(tmp_path):
    api = make_api(tmp_path, schedule_tick_s=0.05)
    with contextlib.closing(db.connect(api.db_path)) as conn:
        view = schedules.create_schedule(conn, api.clock(), run_type="filesystem", interval_seconds=15, config={"roots": ["C:\\c"]})
    with TestClient(api.app, base_url=BASE_URL) as client:
        time.sleep(0.3)
        assert runs_in(api.db_path) == []                                   # not due yet: a full interval has not passed
        api.clock.advance(15)
        assert wait_for(lambda: len(runs_in(api.db_path)) == 1)
        (run,) = client.get("/api/runs").json()["runs"]
        assert (run["trigger"], run["schedule_id"], run["status"]) == ("scheduled", view["schedule_id"], "queued")
        time.sleep(0.4)                                                     # many more ticks at the same moment: still one run
    assert len(runs_in(api.db_path)) == 1


def test_a_tick_that_raises_does_not_stop_the_loop(tmp_path, monkeypatch, caplog):
    api = make_api(tmp_path, schedule_tick_s=0.02)
    calls = []

    def flaky(app):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom with C:\\secret\\path")
        return schedules.TickResult()
    monkeypatch.setattr(app_module, "tick_once", flaky)
    with caplog.at_level("ERROR", logger="backend.api"):
        with TestClient(api.app, base_url=BASE_URL):
            assert wait_for(lambda: len(calls) >= 4)
            assert not api.app.state.scheduler_task.done()
    assert "RuntimeError" in caplog.text and "secret" not in caplog.text


def test_startup_after_downtime_creates_one_catch_up_run_not_one_per_missed_interval(tmp_path):
    api = make_api(tmp_path, schedule_tick_s=0.02)
    with contextlib.closing(db.connect(api.db_path)) as conn:
        schedules.create_schedule(conn, api.clock(), run_type="filesystem", interval_seconds=15, config={"roots": ["C:\\c"]})
    api.clock.advance(15 * 50)                                              # fifty intervals while the backend was "down"
    with TestClient(api.app, base_url=BASE_URL):
        assert wait_for(lambda: len(runs_in(api.db_path)) == 1)
        time.sleep(0.4)
    assert len(runs_in(api.db_path)) == 1


def test_the_api_keeps_answering_while_the_scheduler_ticks(tmp_path):
    api = make_api(tmp_path, schedule_tick_s=0.01)
    with TestClient(api.app, base_url=BASE_URL) as client:
        for _ in range(30):
            assert client.get("/api/schedules").status_code == 200 and client.get("/api/runs").status_code == 200


# =========================================================================== several instances, one database
def test_two_application_instances_on_one_database_create_one_run_per_due_occurrence(tmp_path, monkeypatch):
    """Both instances tick every 20 ms against the same file. With the overlap rule disabled, only the claim of the occurrence
    (re-read and conditional update in one write transaction) stands between them and a duplicate run."""
    monkeypatch.setattr(schedules, "_run_is_active", lambda conn: False)
    first = make_api(tmp_path, name="shared.db", schedule_tick_s=0.02)
    second = make_api(tmp_path, name="shared.db", clock=first.clock, schedule_tick_s=0.02)
    with contextlib.closing(db.connect(first.db_path)) as conn:
        schedules.create_schedule(conn, first.clock(), run_type="filesystem", interval_seconds=15, config={"roots": ["C:\\c"]})
    first.clock.advance(15)
    with TestClient(first.app, base_url=BASE_URL), TestClient(second.app, base_url=BASE_URL):
        assert wait_for(lambda: len(runs_in(first.db_path)) >= 1)
        time.sleep(0.6)
        assert len(runs_in(first.db_path)) == 1                              # first occurrence: exactly one run
        first.clock.advance(15)
        assert wait_for(lambda: len(runs_in(first.db_path)) >= 2)
        time.sleep(0.6)
    assert len(runs_in(first.db_path)) == 2                                  # second occurrence: exactly one more
    assert all(r["run_trigger"] == "scheduled" for r in runs_in(first.db_path))


def test_two_instances_with_the_overlap_rule_on_also_create_one_run_and_the_occurrence_is_dropped_not_queued(tmp_path):
    first = make_api(tmp_path, name="shared2.db", schedule_tick_s=0.02)
    second = make_api(tmp_path, name="shared2.db", clock=first.clock, schedule_tick_s=0.02)
    with contextlib.closing(db.connect(first.db_path)) as conn:
        view = schedules.create_schedule(conn, first.clock(), run_type="filesystem", interval_seconds=15, config={"roots": ["C:\\c"]})
    first.clock.advance(15)
    with TestClient(first.app, base_url=BASE_URL), TestClient(second.app, base_url=BASE_URL):
        assert wait_for(lambda: len(runs_in(first.db_path)) == 1)
        first.clock.advance(15)                                              # next occurrence while the first run is still queued
        time.sleep(0.5)
        assert len(runs_in(first.db_path)) == 1                              # skipped, not queued up behind it
        with contextlib.closing(db.connect(first.db_path)) as conn:
            after = schedules.get_schedule(conn, view["schedule_id"])
        assert after["next_due_at"] > "2026-03-01T12:00:30.000Z" and after["run_count"] == 1
