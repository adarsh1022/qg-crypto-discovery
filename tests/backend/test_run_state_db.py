"""The pure state machine and the database must agree: same transitions, and every state the
functions can produce is storable (the schema's CHECK constraints accept it)."""
import datetime as dt
import itertools
import sqlite3

import pytest

from backend import run_state as rs
from backend.run_state import AgentReport, Counts, RunState
from dbfixtures import insert, run_row

T0 = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=dt.timezone.utc)


def at(seconds):
    return T0 + dt.timedelta(seconds=seconds)


def store(conn, state: RunState, **extra) -> str:
    row = run_row(**{**state.to_columns(), **extra})
    insert(conn, "runs", row)
    return row["run_id"]


def reachable_states():
    """Every kind of state the pure functions can produce."""
    queued = rs.new_run(T0)
    running = rs.start(queued, at(1))
    busy = rs.update_counts(rs.heartbeat(running, at(5)), Counts(records=9, findings=7, rejected=1, errors=2))
    flagged = rs.request_cancel(running, at(2))
    clean = AgentReport(outcome="finished", stop_reason="completed", coverage_started=True)
    return {
        "queued": queued,
        "running": running,
        "running with progress": busy,
        "running, cancel requested": flagged,
        "completed": rs.finish(busy, at(10), Counts(records=9, findings=9), clean),
        "completed, nothing found": rs.finish(running, at(10), Counts(), clean),
        "partial: file errors": rs.finish(busy, at(10), Counts(records=9, findings=7, errors=2), clean),
        "partial: time limit": rs.finish(busy, at(10), Counts(records=9), AgentReport(
            outcome="finished", stop_reason="time_limit", coverage_started=True)),
        "partial: cancelled": rs.finish(flagged, at(10), Counts(records=3), AgentReport(
            outcome="finished", stop_reason="cancelled", coverage_started=True)),
        "partial: agent lost": rs.expire(busy, at(1000), queue_timeout_s=1, heartbeat_timeout_s=1),
        "failed: agent failure": rs.finish(busy, at(10), Counts(records=9), AgentReport(outcome="failed", fatal_code="boom")),
        "failed: no usable data": rs.finish(running, at(10), Counts(), AgentReport(outcome="lost")),
        "failed: queue timeout": rs.expire(queued, at(1000), queue_timeout_s=1, heartbeat_timeout_s=1),
        "failed: cancelled while queued": rs.request_cancel(queued, at(3)),
        "failed: clock went backwards": rs.finish(running, at(-50), Counts(records=1), clean),
    }


@pytest.mark.parametrize("name", list(reachable_states()))
def test_every_state_the_functions_produce_is_storable(conn, name):
    state = reachable_states()[name]
    run_id = store(conn, state)
    row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    assert RunState.from_row(row) == state                              # lossless round trip through SQLite


def test_the_database_enforces_the_same_transition_table(conn):
    """For all 25 (from, to) pairs: the trigger accepts exactly what run_state.TRANSITIONS allows."""
    shapes = {   # a valid row for each status
        "queued": dict(),
        "running": dict(started_at="2026-03-01T12:00:01.000Z", lease_hash="d" * 64),
        "completed": dict(started_at="2026-03-01T12:00:01.000Z", finished_at="2026-03-01T12:00:02.000Z", duration_ms=1000),
        "partial": dict(started_at="2026-03-01T12:00:01.000Z", finished_at="2026-03-01T12:00:02.000Z", duration_ms=1000,
                        error_summary="x"),
        "failed": dict(started_at="2026-03-01T12:00:01.000Z", finished_at="2026-03-01T12:00:02.000Z", duration_ms=1000,
                       error_summary="x"),
    }
    assert set(shapes) == set(rs.STATUSES)
    for src, dst in itertools.product(rs.STATUSES, rs.STATUSES):
        row = run_row(status=src, **shapes[src])
        insert(conn, "runs", row)
        # change only the status and bring the other columns to the target shape in the same UPDATE
        target = {"started_at": None, "finished_at": None, "duration_ms": None, "error_summary": None}
        target.update(shapes[dst])
        assignments = ", ".join(f"{k} = ?" for k in ("status", *target))
        try:
            conn.execute(f"UPDATE runs SET {assignments} WHERE run_id = ?", (dst, *target.values(), row["run_id"]))
            accepted = True
        except sqlite3.IntegrityError as exc:
            accepted = False
            assert "invalid run status transition" in str(exc), (src, dst, str(exc))
        expected = src == dst or rs.can_transition(src, dst)
        assert accepted == expected, f"{src} -> {dst}: database accepted={accepted}, state machine allows={expected}"


def test_a_terminal_run_cannot_be_reopened_in_the_database(conn):
    finished = rs.finish(rs.start(rs.new_run(T0), at(1)), at(2), Counts(records=1),
                         AgentReport(outcome="finished", stop_reason="completed", coverage_started=True))
    run_id = store(conn, finished)
    with pytest.raises(sqlite3.IntegrityError, match="invalid run status transition"):
        conn.execute("UPDATE runs SET status = 'running', lease_hash = ?, finished_at = NULL, duration_ms = NULL WHERE run_id = ?",
                     ("e" * 64, run_id))


def test_a_full_lifecycle_through_the_database(conn):
    """queued -> running (heartbeat, progress) -> partial, persisted at each step."""
    state = rs.new_run(T0)
    run_id = store(conn, state)

    def save(new):
        columns = new.to_columns()
        if new.status != "queued":
            columns["lease_hash"] = "f" * 64              # the claim sets the lease once; later saves repeat the same value
        conn.execute("UPDATE runs SET " + ", ".join(f"{k} = ?" for k in columns) + " WHERE run_id = ?",
                     (*columns.values(), run_id))
        return RunState.from_row(conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone())

    state = save(rs.start(state, at(1)))
    state = save(rs.heartbeat(state, at(30)))
    state = save(rs.update_counts(state, Counts(records=100, findings=90, rejected=0, errors=4)))
    state = save(rs.finish(state, at(61), Counts(records=100, findings=90, errors=4),
                           AgentReport(outcome="finished", stop_reason="completed", coverage_started=True)))
    assert (state.status, state.duration_ms, state.error_summary) == ("partial", 60000, "file_errors:4")
    assert (state.record_count, state.finding_count, state.error_count) == (100, 90, 4)
