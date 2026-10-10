"""Scheduling rules at the domain level: validation, timing, overlap, catch-up, duplicate prevention, isolation of failures.

A fake clock and a real SQLite file (threads and several connections need a file). Nothing here uses HTTP; test_api_schedules.py
covers the API, test_schedule_lifecycle.py the background task.

Note on ordering: due schedules are handled oldest-due first, and because the agent runs one thing at a time, the first one that
creates a run blocks the rest for that tick. Tests that involve several schedules therefore give them different due times."""
import contextlib
import datetime as dt
import json
import logging
import re
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest

from backend import db, fs_ingest, run_state as rs, runs, schedules, service
from backend.errors import ApiError
from backend.settings import Settings

UTC = dt.timezone.utc
START = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
TS = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z")


def at(seconds: float) -> dt.datetime:
    return START + dt.timedelta(seconds=seconds)


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "schedules.db"
    db.open_database(path).close()
    ctx = service.Context(settings=Settings(db_path=path, sweep_interval_s=None, schedule_tick_s=None), not_before=START)
    conn = db.connect(path)
    yield SimpleNamespace(conn=conn, ctx=ctx, path=path)
    conn.close()


def make(env, interval=60, *, now=0, run_type="filesystem", config=None, enabled=True, probe_all=False):
    if config is None:
        config = {"roots": ["C:\\certs"]} if run_type == "filesystem" else {"ports": [8443]}
    return schedules.create_schedule(env.conn, at(now), run_type=run_type, interval_seconds=interval, config=config,
                                     enabled=enabled, probe_all_listeners=probe_all)


def tick(env, now):
    return schedules.tick(env.conn, env.ctx, at(now))


def all_runs(env):
    return [dict(r) for r in env.conn.execute("SELECT * FROM runs ORDER BY run_number")]


def raw(env, schedule_id):
    return dict(env.conn.execute("SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)).fetchone())


def end_run(env, run_id, now=0):
    """End a run that has not finished, the way the lifecycle fails a run nobody picked up."""
    with db.transaction(env.conn):
        runs.fail_run_in_tx(env.conn, run_id, now=at(now), code="agent_not_connected")


def code_of(excinfo):
    return excinfo.value.code, excinfo.value.details


# =========================================================================== interval
@pytest.mark.parametrize("interval", [15, 16, 59, 3600, 86400, 604799, 604800])
def test_intervals_from_15_seconds_to_7_days_inclusive_are_accepted(env, interval):
    view = make(env, interval)
    assert view["interval_seconds"] == interval
    assert view["next_due_at"] == rs.format_ts(at(interval))                     # first run: one full interval after creation


@pytest.mark.parametrize("interval", [14, 1, 0, -1, -60, 604801, 10**9, True, False, 30.0, 30.5, 15.0, "30", "", None, [30], {"s": 30}])
def test_other_intervals_are_refused_and_nothing_is_stored(env, interval):
    with pytest.raises(ApiError) as bad:
        make(env, interval)
    assert code_of(bad) == ("invalid_schedule", {"field": "interval_seconds", "problem": "out_of_range", "min": 15, "max": 604800})
    assert env.conn.execute("SELECT COUNT(*) FROM schedules").fetchone()[0] == 0


def test_an_unknown_run_type_is_refused(env):
    with pytest.raises(ApiError) as bad:
        schedules.create_schedule(env.conn, at(0), run_type="dns", interval_seconds=60, config={})
    assert code_of(bad) == ("invalid_schedule", {"field": "run_type", "problem": "unknown_type"})


# =========================================================================== configuration
@pytest.mark.parametrize("config", [{"unknown": 1}, {"roots": "C:\\a"}, {"roots": [1]}, {"max_depth": -1}, {"time_budget_seconds": 0},
                                    {"max_file_bytes": True}, {"expiring_days": None}])
def test_a_filesystem_configuration_gets_exactly_the_checks_a_manual_run_gets(env, config):
    with pytest.raises(ApiError) as bad:
        make(env, config=config)
    assert bad.value.code == "invalid_config" and env.conn.execute("SELECT COUNT(*) FROM schedules").fetchone()[0] == 0


@pytest.mark.parametrize("config", [{"hosts": ["8.8.8.8"]}, {"ports": []}, {"ports": [0]}, {"ports": [65536]}, {"ports": ["443"]},
                                    {"ports": [True]}, {"ports": list(range(1, 258))}, {"max_targets": 0}, {"max_targets": 1025},
                                    {"connect_timeout_seconds": 31}, {"time_budget_seconds": 3601}, {"handshake_timeout_seconds": 0}])
def test_a_tls_configuration_is_constrained_like_a_manual_tls_run_and_can_never_name_a_target(env, config):
    with pytest.raises(ApiError) as bad:
        make(env, run_type="tls", config=config)
    assert bad.value.code == "invalid_config"


@pytest.mark.parametrize("config", [{"roots": ["-----BEGIN CERTIFICATE-----"]}, {"exclude_paths": ["C:\\x\n-----BEGIN PRIVATE KEY-----"]},
                                    {"private_key": "x"}, {"nested": {"password": "p"}}, {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}])
def test_key_material_cannot_be_smuggled_into_a_schedule_and_is_not_echoed(env, config):
    with pytest.raises(ApiError) as bad:
        make(env, config=config)
    assert bad.value.code == "invalid_config"
    body = json.dumps(bad.value.body())
    assert "BEGIN" not in body and "password" not in body and "private_key" not in body


def test_the_opt_in_key_cannot_be_sneaked_in_through_the_configuration(env):
    with pytest.raises(ApiError) as bad:
        make(env, run_type="tls", config={"probe_all_listeners": True})
    assert bad.value.code == "invalid_config" and bad.value.details["problem"] == "unknown_key"


# =========================================================================== TLS broad-probe opt-in
def test_a_tls_schedule_without_ports_requires_the_explicit_opt_in(env):
    for config in ({}, {"max_targets": 5}, {"time_budget_seconds": 30}):
        with pytest.raises(ApiError) as bad:
            make(env, run_type="tls", config=config, probe_all=False)
        assert code_of(bad) == ("invalid_schedule", {"field": "probe_all_listeners", "problem": "required_without_ports"})
    assert env.conn.execute("SELECT COUNT(*) FROM schedules").fetchone()[0] == 0


def test_with_the_opt_in_a_tls_schedule_is_stored_as_such_and_shown_as_such(env):
    view = make(env, run_type="tls", config={"max_targets": 5}, probe_all=True)
    assert view["probe_all_listeners"] is True and view["config"] == {"max_targets": 5}   # the flag is not part of the run config
    assert json.loads(raw(env, view["schedule_id"])["config_json"]) == {"max_targets": 5, "probe_all_listeners": True}


def test_explicit_ports_need_no_opt_in_and_the_opt_in_may_not_be_combined_with_them(env):
    view = make(env, run_type="tls", config={"ports": [8443, 9443]}, probe_all=False)
    assert view["probe_all_listeners"] is False and view["config"] == {"ports": [8443, 9443]}
    with pytest.raises(ApiError) as bad:
        make(env, run_type="tls", config={"ports": [8443]}, probe_all=True)
    assert code_of(bad) == ("invalid_schedule", {"field": "probe_all_listeners", "problem": "conflicts_with_ports"})


def test_the_opt_in_is_a_tls_only_notion(env):
    with pytest.raises(ApiError) as bad:
        make(env, run_type="filesystem", probe_all=True)
    assert code_of(bad) == ("invalid_schedule", {"field": "probe_all_listeners", "problem": "tls_only"})


def test_a_tls_run_created_by_an_opted_in_schedule_carries_the_run_config_without_the_flag(env):
    view = make(env, run_type="tls", config={}, probe_all=True)
    tick(env, 60)
    (run,) = all_runs(env)
    assert run["type"] == "tls" and json.loads(run["config_json"]) == {} and run["run_trigger"] == "scheduled"
    assert run["schedule_id"] == view["schedule_id"]


def test_the_opt_in_is_checked_again_every_time_a_schedule_fires(env, caplog):
    """A row that reached the table some other way (hand edit, bug) cannot start a broad probe: it needs the stored opt-in."""
    broken = make(env, 30, run_type="tls", config={"ports": [8443]})            # due first
    healthy = make(env, 60, run_type="filesystem")
    env.conn.execute("UPDATE schedules SET config_json = '{}' WHERE schedule_id = ?", (broken["schedule_id"],))   # ports removed by hand
    with caplog.at_level(logging.ERROR, logger="backend.schedules"):
        result = tick(env, 60)
    assert (result.created, result.failed) == (1, 1)
    assert [r["schedule_id"] for r in all_runs(env)] == [healthy["schedule_id"]]
    assert "opt-in" in caplog.text and broken["schedule_id"] in caplog.text


# =========================================================================== timing
def test_nothing_is_due_before_one_full_interval_and_exactly_one_run_is_created_when_it_is(env):
    view = make(env, 60)
    assert tick(env, 0) == schedules.TickResult() and tick(env, 59.999) == schedules.TickResult()
    assert all_runs(env) == []
    assert tick(env, 60) == schedules.TickResult(created=1)
    (run,) = all_runs(env)
    assert (run["type"], run["run_trigger"], run["schedule_id"], run["status"]) == ("filesystem", "scheduled", view["schedule_id"], "queued")
    assert json.loads(run["config_json"]) == {"roots": ["C:\\certs"]} and run["queued_at"] == rs.format_ts(at(60))


def test_the_schedule_remembers_the_run_and_moves_its_next_due_time_one_interval_on(env):
    view = make(env, 60)
    tick(env, 61)
    (run,) = all_runs(env)
    after = schedules.get_schedule(env.conn, view["schedule_id"])
    assert after["next_due_at"] == rs.format_ts(at(61 + 60)) and TS.fullmatch(after["next_due_at"])
    assert after["last_run"] == {"run_id": run["run_id"], "run_number": 1, "status": "queued", "queued_at": run["queued_at"], "finished_at": None}
    assert after["run_count"] == 1


def test_a_second_tick_for_the_same_moment_creates_nothing(env):
    make(env, 60)
    assert tick(env, 60).created == 1
    assert tick(env, 60) == schedules.TickResult() and tick(env, 61) == schedules.TickResult()
    assert len(all_runs(env)) == 1


def test_a_clock_that_goes_backwards_creates_nothing(env):
    make(env, 60)
    tick(env, 60)
    assert tick(env, 10) == schedules.TickResult() and len(all_runs(env)) == 1


def test_times_given_in_another_time_zone_are_stored_as_utc(env):
    local = dt.timezone(dt.timedelta(hours=5, minutes=30))
    view = schedules.create_schedule(env.conn, START.astimezone(local), run_type="filesystem", interval_seconds=60,
                                     config={"roots": ["C:\\c"]})
    assert view["created_at"] == "2026-03-01T12:00:00.000Z" and view["next_due_at"] == "2026-03-01T12:01:00.000Z"


def test_due_schedules_are_handled_oldest_due_first_and_the_first_run_blocks_the_rest_for_that_tick(env):
    a, b, c = make(env, 30), make(env, 40), make(env, 500)
    result = tick(env, 45)                                                  # a (due at 30) and b (due at 40); c is not due
    assert result == schedules.TickResult(created=1, skipped=1)
    assert [r["schedule_id"] for r in all_runs(env)] == [a["schedule_id"]]
    assert raw(env, b["schedule_id"])["next_due_at"] == rs.format_ts(at(45 + 40))      # b's occurrence was dropped, not queued up
    assert raw(env, c["schedule_id"])["next_due_at"] == rs.format_ts(at(500))          # c was never touched


# =========================================================================== catch-up after downtime
def test_after_downtime_exactly_one_catch_up_run_is_created_and_nothing_is_replayed(env):
    view = make(env, 60)
    assert tick(env, 60 * 10 + 5).created == 1                             # ten intervals missed
    assert len(all_runs(env)) == 1
    assert schedules.get_schedule(env.conn, view["schedule_id"])["next_due_at"] == rs.format_ts(at(605 + 60))
    end_run(env, all_runs(env)[0]["run_id"], 606)
    assert tick(env, 606 + 30) == schedules.TickResult() and len(all_runs(env)) == 1      # no backlog is waiting


def test_a_restart_fires_an_overdue_schedule_once(tmp_path):
    path = tmp_path / "restart.db"
    db.open_database(path).close()
    settings = Settings(db_path=path, sweep_interval_s=None, schedule_tick_s=None)
    with contextlib.closing(db.connect(path)) as first:
        schedules.create_schedule(first, at(0), run_type="filesystem", interval_seconds=60, config={"roots": ["C:\\c"]})
    for _ in range(3):                                                      # three "restarts" at the same late moment
        with contextlib.closing(db.connect(path)) as conn:
            schedules.tick(conn, service.Context(settings=settings, not_before=at(1000)), at(1000))
    with contextlib.closing(db.connect(path)) as check:
        assert check.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1


# =========================================================================== overlap
def test_an_occurrence_is_skipped_while_the_schedules_own_previous_run_is_queued_and_the_next_due_time_advances(env):
    view = make(env, 60)
    tick(env, 60)
    assert tick(env, 120) == schedules.TickResult(skipped=1) and len(all_runs(env)) == 1
    after = schedules.get_schedule(env.conn, view["schedule_id"])
    assert after["next_due_at"] == rs.format_ts(at(180)) and after["last_run"]["status"] == "queued" and after["run_count"] == 1


def test_an_occurrence_is_skipped_while_a_run_is_running(env):
    make(env, 60)
    run_id = runs.create_run(env.conn, "filesystem", "manual", now=at(0), config={"roots": ["C:\\c"]})
    runs.start_run(env.conn, run_id, now=at(30))
    assert tick(env, 60) == schedules.TickResult(skipped=1) and len(all_runs(env)) == 1


@pytest.mark.parametrize("run_type, config", [("filesystem", {"roots": ["C:\\c"]}), ("tls", {"ports": [443]})])
def test_a_run_of_ANY_kind_blocks_every_schedule(env, run_type, config):
    make(env, 60)
    make(env, 60, run_type="tls", config={"ports": [8443]})
    runs.create_run(env.conn, run_type, "manual", now=at(0), config=config)
    assert tick(env, 60) == schedules.TickResult(skipped=2) and len(all_runs(env)) == 1


@pytest.mark.parametrize("how", ["failed_by_lifecycle", "finalized_as_failed"])
def test_a_finished_previous_run_does_not_block_the_next_one(env, how):
    view = make(env, 60)
    tick(env, 60)
    run_id = all_runs(env)[0]["run_id"]
    if how == "failed_by_lifecycle":
        end_run(env, run_id, 70)
    else:
        runs.start_run(env.conn, run_id, now=at(70))
        with db.transaction(env.conn):
            fs_ingest.finalize_fs_run_in_tx(env.conn, run_id, now=at(80), outcome="failed", fatal_code="boom")
    assert schedules.get_schedule(env.conn, view["schedule_id"])["last_run"]["status"] == "failed"
    assert tick(env, 120).created == 1 and len(all_runs(env)) == 2


def test_a_stale_queued_run_is_expired_by_the_normal_lifecycle_first_so_it_does_not_block_a_schedule_forever(env):
    make(env, 60)
    stale = runs.create_run(env.conn, "filesystem", "manual", now=at(0), config={"roots": ["C:\\c"]})
    assert tick(env, 60).skipped == 1                                      # 60 s old: still within the 120 s queue timeout
    assert tick(env, 120 + 60).created == 1                                # now 180 s old: expired, and the schedule fires
    old = runs.get_run(env.conn, stale)
    assert old["status"] == "failed" and old["error_summary"] == "agent_not_connected"
    assert [r["run_trigger"] for r in all_runs(env)] == ["manual", "scheduled"]


def test_a_stale_running_run_whose_agent_vanished_is_expired_first_too(env):
    make(env, 60)
    run_id = runs.create_run(env.conn, "filesystem", "manual", now=at(0), config={"roots": ["C:\\c"]})
    runs.start_run(env.conn, run_id, now=at(0))
    assert tick(env, 60).skipped == 1                                      # last heartbeat 60 s ago: still alive
    assert tick(env, 300).created == 1                                     # no heartbeat for 300 s: lost, and the schedule fires
    assert runs.get_run(env.conn, run_id)["status"] in ("failed", "partial")


def test_a_failure_while_expiring_stale_runs_only_makes_the_tick_cautious_it_does_not_stop_it(env, monkeypatch, caplog):
    make(env, 60)
    monkeypatch.setattr(service, "sweep", lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError("secret C:\\path")))
    with caplog.at_level(logging.ERROR, logger="backend.schedules"):
        assert tick(env, 60).created == 1
    assert "OperationalError" in caplog.text and "secret" not in caplog.text and "C:\\path" not in caplog.text


# =========================================================================== pause and resume
def test_pausing_clears_the_next_due_time_and_a_paused_schedule_never_fires(env):
    view = make(env, 60)
    paused = schedules.set_enabled(env.conn, at(10), view["schedule_id"], False)
    assert (paused["enabled"], paused["state"], paused["next_due_at"]) == (False, "paused", None)
    assert raw(env, view["schedule_id"])["next_due_at"] is None
    assert tick(env, 10_000) == schedules.TickResult() and all_runs(env) == []


def test_a_paused_schedule_with_a_stale_due_time_in_the_table_still_does_not_fire(env):
    view = make(env, 60)
    env.conn.execute("UPDATE schedules SET enabled = 0 WHERE schedule_id = ?", (view["schedule_id"],))   # due time left behind
    assert tick(env, 10_000) == schedules.TickResult() and all_runs(env) == []


def test_resuming_waits_one_full_interval_instead_of_firing_for_the_time_it_was_paused(env):
    view = make(env, 60)
    schedules.set_enabled(env.conn, at(10), view["schedule_id"], False)
    resumed = schedules.set_enabled(env.conn, at(100_000), view["schedule_id"], True)
    assert (resumed["enabled"], resumed["state"], resumed["next_due_at"]) == (True, "waiting", rs.format_ts(at(100_060)))
    assert tick(env, 100_059) == schedules.TickResult() and tick(env, 100_060).created == 1


def test_pause_and_resume_are_idempotent_and_a_repeated_resume_does_not_move_the_clock(env):
    view = make(env, 60)
    first = schedules.set_enabled(env.conn, at(5), view["schedule_id"], True)
    assert first["next_due_at"] == rs.format_ts(at(60))                    # already enabled: unchanged
    schedules.set_enabled(env.conn, at(10), view["schedule_id"], False)
    schedules.set_enabled(env.conn, at(20), view["schedule_id"], False)
    a = schedules.set_enabled(env.conn, at(30), view["schedule_id"], True)
    b = schedules.set_enabled(env.conn, at(40), view["schedule_id"], True)
    assert a["next_due_at"] == b["next_due_at"] == rs.format_ts(at(90))


def test_a_schedule_can_be_created_paused_and_then_has_no_due_time(env):
    view = make(env, 60, enabled=False)
    assert (view["enabled"], view["state"], view["next_due_at"]) == (False, "paused", None)
    assert tick(env, 10_000) == schedules.TickResult()


def test_pausing_or_resuming_an_unknown_schedule_is_a_clean_404(env):
    with pytest.raises(ApiError) as bad:
        schedules.set_enabled(env.conn, at(0), "sched-nope", False)
    assert (bad.value.status, bad.value.code) == (404, "schedule_not_found")
    with pytest.raises(ApiError) as bad:
        schedules.get_schedule(env.conn, "sched-nope")
    assert bad.value.code == "schedule_not_found"


# =========================================================================== truthful states
def test_the_state_says_waiting_skipping_or_paused_and_nothing_else(env):
    sid = make(env, 60)["schedule_id"]
    assert schedules.get_schedule(env.conn, sid)["state"] == "waiting"
    run_id = runs.create_run(env.conn, "filesystem", "manual", now=at(0), config={"roots": ["C:\\c"]})
    assert schedules.get_schedule(env.conn, sid)["state"] == "skipping"        # a run is queued: an occurrence due now would be skipped
    runs.start_run(env.conn, run_id, now=at(1))
    assert schedules.get_schedule(env.conn, sid)["state"] == "skipping"        # ... or running
    schedules.set_enabled(env.conn, at(2), sid, False)
    assert schedules.get_schedule(env.conn, sid)["state"] == "paused"          # paused wins
    schedules.set_enabled(env.conn, at(3), sid, True)
    end_run(env, run_id, 4)
    assert schedules.get_schedule(env.conn, sid)["state"] == "waiting"
    assert {s["state"] for s in schedules.list_schedules(env.conn)} <= set(schedules.STATES)


def test_the_last_run_reports_the_real_lifecycle_status_never_completed_early(env):
    view = make(env, 60)
    tick(env, 60)
    sid = view["schedule_id"]
    assert schedules.get_schedule(env.conn, sid)["last_run"]["status"] == "queued"
    run_id = all_runs(env)[0]["run_id"]
    runs.start_run(env.conn, run_id, now=at(70))
    assert schedules.get_schedule(env.conn, sid)["last_run"]["status"] == "running"
    end_run(env, run_id, 80)
    last = schedules.get_schedule(env.conn, sid)["last_run"]
    assert last["status"] == "failed" and last["finished_at"] == rs.format_ts(at(80))


# =========================================================================== provenance
def test_scheduled_runs_carry_trigger_and_schedule_id_and_the_public_path_cannot_create_them(env):
    view = make(env, 60)
    tick(env, 60)
    (run,) = all_runs(env)
    assert (run["run_trigger"], run["schedule_id"]) == ("scheduled", view["schedule_id"])
    for trigger, schedule_id in (("scheduled", view["schedule_id"]), ("manual", view["schedule_id"]), ("scheduled", None)):
        with pytest.raises(ApiError) as bad:
            service.create_run(env.conn, env.ctx, at(0), run_type="filesystem", trigger=trigger, schedule_id=schedule_id, config={})
        assert bad.value.code == "scheduled_runs_reserved"
    assert len(all_runs(env)) == 1


def test_the_stored_run_config_is_a_copy_of_the_schedules(env):
    view = make(env, 60, config={"roots": ["C:\\a"], "max_depth": 3})
    tick(env, 60)
    assert json.loads(all_runs(env)[0]["config_json"]) == {"roots": ["C:\\a"], "max_depth": 3}
    assert schedules.get_schedule(env.conn, view["schedule_id"])["config"] == {"roots": ["C:\\a"], "max_depth": 3}


# =========================================================================== isolation of failures
def test_one_schedule_failing_does_not_stop_the_others_and_its_own_changes_are_rolled_back(env, monkeypatch, caplog):
    b = make(env, 30)                                                       # due first: it is the one that fails
    a = make(env, 40)
    c = make(env, 50)
    real = runs.create_run_in_tx

    def flaky(conn, run_type, trigger, **kwargs):
        if kwargs.get("schedule_id") == b["schedule_id"]:
            raise sqlite3.OperationalError("disk I/O error near C:\\Users\\secret\\evidence.db")
        return real(conn, run_type, trigger, **kwargs)
    monkeypatch.setattr(runs, "create_run_in_tx", flaky)
    due_before = raw(env, b["schedule_id"])["next_due_at"]
    with caplog.at_level(logging.ERROR, logger="backend.schedules"):
        result = tick(env, 60)
    assert result == schedules.TickResult(created=1, skipped=1, failed=1)    # b failed; a still ran; c was skipped behind a's run
    assert [r["schedule_id"] for r in all_runs(env)] == [a["schedule_id"]]
    after = raw(env, b["schedule_id"])
    assert after["next_due_at"] == due_before and after["last_run_id"] is None      # rolled back: still due, nothing half-done
    assert raw(env, c["schedule_id"])["next_due_at"] == rs.format_ts(at(60 + 50))
    assert "OperationalError" in caplog.text and b["schedule_id"] in caplog.text
    assert "secret" not in caplog.text and "evidence.db" not in caplog.text and "C:\\certs" not in caplog.text


def test_a_failed_schedule_is_picked_up_again_by_a_later_tick(env, monkeypatch):
    view = make(env, 60)
    real = runs.create_run_in_tx
    monkeypatch.setattr(runs, "create_run_in_tx", lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError("locked")))
    assert tick(env, 60).failed == 1 and all_runs(env) == []
    monkeypatch.setattr(runs, "create_run_in_tx", real)
    assert tick(env, 65).created == 1
    assert [r["schedule_id"] for r in all_runs(env)] == [view["schedule_id"]]


def test_a_schedule_whose_stored_config_became_invalid_is_logged_once_per_interval_not_once_per_tick(env, caplog):
    view = make(env, 60)
    env.conn.execute("UPDATE schedules SET config_json = ? WHERE schedule_id = ?", ('{"roots": "not a list"}', view["schedule_id"]))
    with caplog.at_level(logging.ERROR, logger="backend.schedules"):
        assert tick(env, 60).failed == 1
        assert tick(env, 65) == schedules.TickResult() and tick(env, 70) == schedules.TickResult()
    assert caplog.text.count(view["schedule_id"]) == 1 and all_runs(env) == []
    assert "not a list" not in caplog.text and "roots" not in caplog.text            # the content is never quoted, only a fixed reason
    assert "no longer valid" in caplog.text
    assert raw(env, view["schedule_id"])["next_due_at"] == rs.format_ts(at(120))


def test_an_invalid_schedule_does_not_stop_a_healthy_one_behind_it(env):
    broken = make(env, 30)
    healthy = make(env, 60)
    env.conn.execute("UPDATE schedules SET config_json = '{\"bogus_key\": 1}' WHERE schedule_id = ?", (broken["schedule_id"],))
    assert tick(env, 60) == schedules.TickResult(created=1, failed=1)
    assert [r["schedule_id"] for r in all_runs(env)] == [healthy["schedule_id"]]


# =========================================================================== duplicate prevention
def _run_threads(env, count, body):
    barrier = threading.Barrier(count)
    failures = []

    def worker():
        conn = db.connect(env.path)
        try:
            barrier.wait()
            body(conn)
        except Exception as exc:                                            # noqa: BLE001
            failures.append(repr(exc))
        finally:
            conn.close()
    threads = [threading.Thread(target=worker) for _ in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not failures, failures


def test_concurrent_ticks_on_separate_connections_create_exactly_one_run(env):
    for _ in range(5):
        make(env, 60)
    results = []
    _run_threads(env, 8, lambda conn: results.append(schedules.tick(conn, env.ctx, at(60))))
    assert len(results) == 8 and sum(r.created for r in results) == 1
    assert len(all_runs(env)) == 1


def test_the_occurrence_guard_alone_stops_duplicates_even_with_the_overlap_rule_switched_off(env, monkeypatch):
    """Overlap is a second line of defence. With it disabled, concurrent ticks must STILL create one run per occurrence,
    because each schedule is claimed (re-read and conditionally updated) inside one write transaction."""
    ids = [make(env, 60)["schedule_id"] for _ in range(4)]
    monkeypatch.setattr(schedules, "_run_is_active", lambda conn: False)
    results = []
    _run_threads(env, 8, lambda conn: results.append(schedules.tick(conn, env.ctx, at(60))))
    assert sum(r.created for r in results) == 4                            # one per schedule, not 4 x 8
    runs_by_schedule = [r["schedule_id"] for r in all_runs(env)]
    assert sorted(runs_by_schedule) == sorted(ids)


def test_repeated_ticks_for_one_occurrence_while_others_race_never_exceed_one_run(env, monkeypatch):
    make(env, 60)
    monkeypatch.setattr(schedules, "_run_is_active", lambda conn: False)
    stop = threading.Event()
    created = []

    def body(conn):
        while not stop.is_set():
            created.append(schedules.tick(conn, env.ctx, at(60)).created)
    threads = [threading.Thread(target=lambda: body(db.connect(env.path))) for _ in range(4)]
    for t in threads:
        t.start()
    time.sleep(0.5)
    stop.set()
    for t in threads:
        t.join(timeout=60)
    assert sum(created) == 1 and len(all_runs(env)) == 1


class _LosingTheRace:
    """A connection whose conditional claim never matches, as if another tick had changed the due time in between."""

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def execute(self, sql, params=()):
        if sql.startswith("UPDATE schedules SET next_due_at"):
            params = (*params[:-1], "1999-01-01T00:00:00.000Z")           # the due time we "read" is no longer the stored one
        return self._real.execute(sql, params)


def test_a_claim_that_loses_the_race_creates_nothing_and_changes_nothing(env):
    view = make(env, 60)
    before = raw(env, view["schedule_id"])
    assert schedules._fire(_LosingTheRace(env.conn), at(60), view["schedule_id"]) == "superseded"
    assert raw(env, view["schedule_id"]) == before and all_runs(env) == []


def test_firing_a_schedule_that_is_no_longer_due_is_a_no_op(env):
    view = make(env, 60)
    assert schedules._fire(env.conn, at(60), view["schedule_id"]) == "created"
    assert schedules._fire(env.conn, at(60), view["schedule_id"]) == "not_due"           # already claimed and advanced
    with contextlib.closing(db.connect(env.path)) as other:
        schedules.set_enabled(other, at(61), view["schedule_id"], False)
    assert schedules._fire(env.conn, at(10_000), view["schedule_id"]) == "not_due"      # paused in the meantime
    assert len(all_runs(env)) == 1


# =========================================================================== limits and shape
def test_the_number_of_schedules_is_limited(env):
    for _ in range(schedules.MAX_SCHEDULES):
        make(env, 60, enabled=False)
    with pytest.raises(ApiError) as bad:
        make(env, 60)
    assert (bad.value.status, bad.value.code, bad.value.details) == (409, "too_many_schedules", {"max_schedules": 50})
    assert env.conn.execute("SELECT COUNT(*) FROM schedules").fetchone()[0] == 50


def test_schedule_ids_are_generated_unique_and_well_formed(env):
    ids = [make(env, 60, enabled=False)["schedule_id"] for _ in range(20)]
    assert len(set(ids)) == 20 and all(re.fullmatch(r"sched-[0-9a-f]{8}", i) for i in ids)


def test_a_view_has_exactly_the_documented_fields_and_no_internals(env):
    view = make(env, 60)
    assert set(view) == {"schedule_id", "run_type", "interval_seconds", "config", "probe_all_listeners", "enabled", "state",
                         "next_due_at", "created_at", "last_run", "run_count"}
    assert view["last_run"] is None and view["run_count"] == 0
    text = json.dumps(view).lower()
    assert "lease" not in text and "token" not in text and "config_json" not in text


def test_listing_is_oldest_first_and_the_same_from_any_connection(env):
    a, b = make(env, 60), make(env, 90, now=5)
    assert [s["schedule_id"] for s in schedules.list_schedules(env.conn)] == [a["schedule_id"], b["schedule_id"]]
    with contextlib.closing(db.connect(env.path)) as other:
        assert schedules.list_schedules(other) == schedules.list_schedules(env.conn)
