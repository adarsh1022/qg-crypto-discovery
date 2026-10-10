"""Periodic scans: schedules, and the tick that turns a due schedule into one queued run.

A schedule is a row of the existing `schedules` table: a run type, an interval, the run configuration to use, an enabled
flag, the next time it is due and the id of the run it last created. A scheduled run is an ordinary queued run (trigger
'scheduled', schedule_id set) that the agent picks up like any other, so nothing about claiming, leases or ingestion changes.

Rules (all of them are decided here, none in the routes):

* intervals are whole seconds from 15 to 604 800 (7 days) inclusive; a schedule is first due ONE interval after it is created
  or resumed, never at once;
* all stored times are UTC (the same fixed-width format as runs); an interval is a plain duration, not a time of day, so time
  zones and daylight saving cannot move a schedule;
* a due schedule creates at most ONE run, however many intervals were missed (the backend was down, the machine slept), and its
  next due time is then `now + interval`: there is no backlog and nothing is replayed;
* if ANY run is queued or running when a schedule falls due, that occurrence is skipped and the next due time is advanced the
  same way. The agent executes one run at a time, so a run created behind a busy agent would only wait and then fail with a
  misleading "no agent picked up the run". Stale runs are expired with the normal lifecycle logic (service.sweep) first;
* a TLS schedule without an explicit port list probes every eligible listener on the machine, so the backend requires an explicit
  `probe_all_listeners: true` for it, stores that fact with the schedule and checks it again every time the schedule fires;
* a schedule is claimed with a conditional update inside one BEGIN IMMEDIATE transaction that also creates the run, so two ticks
  (threads, loops or application instances on the same database) can never create two runs for the same due occurrence;
* pausing clears the next due time; resuming sets it to now + interval. There is no deletion and no editing in this phase.

Only the scheduler creates scheduled runs: service.create_run (the public path) refuses to.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Any

from . import db, errors, run_state as rs, runs, service
from .errors import ApiError

log = logging.getLogger("backend.schedules")

MIN_INTERVAL_S = 15
MAX_INTERVAL_S = 7 * 24 * 3600
MAX_SCHEDULES = 50
RUN_TYPES = ("filesystem", "tls")
PROBE_ALL_KEY = "probe_all_listeners"         # kept inside the stored configuration of a TLS schedule that has no ports

WAITING, SKIPPING, PAUSED = "waiting", "skipping", "paused"
STATES = (WAITING, SKIPPING, PAUSED)


class _BadSchedule(ValueError):
    """The stored configuration of a schedule can no longer be turned into a valid run."""


@dataclass(frozen=True)
class TickResult:
    created: int = 0          # runs created
    skipped: int = 0          # due occurrences skipped because a run was queued or running
    failed: int = 0           # schedules that could not be processed (logged by id and error class only)
    superseded: int = 0       # occurrences another tick, thread or application instance had already claimed


def _transact(conn: sqlite3.Connection, work):
    """Run `work` in one BEGIN IMMEDIATE transaction; a RETURNED ApiError is raised after the transaction has committed."""
    with db.transaction(conn):
        result = work()
    if isinstance(result, ApiError):
        raise result
    return result


# ------------------------------------------------------------------ validation
def _checked_interval(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not MIN_INTERVAL_S <= value <= MAX_INTERVAL_S:
        raise errors.invalid_schedule({"field": "interval_seconds", "problem": "out_of_range",
                                       "min": MIN_INTERVAL_S, "max": MAX_INTERVAL_S})
    return value


def validated(run_type: str, interval_seconds: Any, config: dict, probe_all_listeners: bool) -> tuple[int, str]:
    """(interval, the configuration text to store) or an ApiError. The configuration goes through exactly the checks a manual
    run's does (known keys, ranges, no key material); the TLS opt-in is enforced here, in the backend."""
    if run_type not in RUN_TYPES:
        raise errors.invalid_schedule({"field": "run_type", "problem": "unknown_type"})
    interval = _checked_interval(interval_seconds)
    config = service.validate_run_config(run_type, config)
    try:
        cleaned = json.loads(runs.clean_json_object(config))
    except ValueError:
        raise errors.invalid_config({"problem": "rejected_content"}) from None
    if run_type != "tls":
        if probe_all_listeners:
            raise errors.invalid_schedule({"field": PROBE_ALL_KEY, "problem": "tls_only"})
    elif "ports" in cleaned:
        if probe_all_listeners:
            raise errors.invalid_schedule({"field": PROBE_ALL_KEY, "problem": "conflicts_with_ports"})
    elif not probe_all_listeners:
        raise errors.invalid_schedule({"field": PROBE_ALL_KEY, "problem": "required_without_ports"})
    else:
        cleaned[PROBE_ALL_KEY] = True
    return interval, runs.clean_json_object(cleaned)


def _run_config(row: sqlite3.Row) -> tuple[str, dict]:
    """The run type and run configuration a stored schedule produces, re-checked every time it fires."""
    try:
        config = json.loads(row["config_json"])
        if not isinstance(config, dict):
            raise _BadSchedule("config is not an object")
        opted_in = config.pop(PROBE_ALL_KEY, None)
        run_type = row["run_type"]
        if run_type == "tls":
            if "ports" not in config and opted_in is not True:
                raise _BadSchedule("a TLS schedule without ports needs the explicit opt-in")
        elif opted_in is not None:
            raise _BadSchedule("only a TLS schedule can carry the opt-in")
        service.validate_run_config(run_type, config)
        runs.clean_json_object(config)
    except _BadSchedule:
        raise                                               # our own checks above: their reason is a fixed sentence
    except (ApiError, ValueError):                          # ValueError includes JSON errors; never quote the content
        raise _BadSchedule("the stored configuration is no longer valid") from None
    return run_type, config


# ------------------------------------------------------------------ views
def _view(conn: sqlite3.Connection, row: sqlite3.Row, run_active: bool) -> dict:
    config = json.loads(row["config_json"])
    probes_all = config.pop(PROBE_ALL_KEY, None) is True
    last = None
    if row["last_run_id"] is not None:
        found = conn.execute("SELECT run_id, run_number, status, queued_at, finished_at FROM runs WHERE run_id = ?",
                             (row["last_run_id"],)).fetchone()
        last = None if found is None else dict(found)
    count = conn.execute("SELECT COUNT(*) FROM runs WHERE schedule_id = ?", (row["schedule_id"],)).fetchone()[0]
    enabled = bool(row["enabled"])
    state = PAUSED if not enabled else SKIPPING if run_active else WAITING
    return {
        "schedule_id": row["schedule_id"], "run_type": row["run_type"], "interval_seconds": row["interval_seconds"],
        "config": config, "probe_all_listeners": probes_all, "enabled": enabled, "state": state,
        "next_due_at": row["next_due_at"] if enabled else None, "created_at": row["created_at"],
        "last_run": last, "run_count": count,
    }


def _run_is_active(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM runs WHERE status IN ('queued', 'running') LIMIT 1").fetchone() is not None


# ------------------------------------------------------------------ operations behind the API
def create_schedule(conn: sqlite3.Connection, now: dt.datetime, *, run_type: str, interval_seconds: Any, config: dict,
                    enabled: bool = True, probe_all_listeners: bool = False) -> dict:
    interval, config_json = validated(run_type, interval_seconds, config, probe_all_listeners)

    def work():
        if conn.execute("SELECT COUNT(*) FROM schedules").fetchone()[0] >= MAX_SCHEDULES:
            return errors.too_many_schedules(MAX_SCHEDULES)
        schedule_id = "sched-" + secrets.token_hex(4)
        while conn.execute("SELECT 1 FROM schedules WHERE schedule_id = ?", (schedule_id,)).fetchone() is not None:
            schedule_id = "sched-" + secrets.token_hex(4)
        due = rs.format_ts(now + dt.timedelta(seconds=interval)) if enabled else None
        conn.execute(
            "INSERT INTO schedules (schedule_id, run_type, interval_seconds, config_json, enabled, next_due_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (schedule_id, run_type, interval, config_json, int(enabled), due, rs.format_ts(now)))
        return schedule_id
    schedule_id = _transact(conn, work)
    return get_schedule(conn, schedule_id)


def list_schedules(conn: sqlite3.Connection) -> list[dict]:
    with db.read_snapshot(conn):
        active = _run_is_active(conn)
        rows = conn.execute("SELECT * FROM schedules ORDER BY created_at, schedule_id").fetchall()
        return [_view(conn, row, active) for row in rows]


def get_schedule(conn: sqlite3.Connection, schedule_id: str) -> dict:
    with db.read_snapshot(conn):
        row = conn.execute("SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)).fetchone()
        if row is None:
            raise errors.schedule_not_found()
        return _view(conn, row, _run_is_active(conn))


def set_enabled(conn: sqlite3.Connection, now: dt.datetime, schedule_id: str, enabled: bool) -> dict:
    """Pause or resume. Repeating the request changes nothing (so a resume never moves a running clock)."""
    def work():
        row = conn.execute("SELECT enabled, interval_seconds FROM schedules WHERE schedule_id = ?", (schedule_id,)).fetchone()
        if row is None:
            return errors.schedule_not_found()
        if bool(row["enabled"]) != enabled:
            due = rs.format_ts(now + dt.timedelta(seconds=row["interval_seconds"])) if enabled else None
            conn.execute("UPDATE schedules SET enabled = ?, next_due_at = ? WHERE schedule_id = ?", (int(enabled), due, schedule_id))
        return None
    _transact(conn, work)
    return get_schedule(conn, schedule_id)


# ------------------------------------------------------------------ the scheduler
def _fire(conn: sqlite3.Connection, now: dt.datetime, schedule_id: str) -> str:
    """Handle one schedule that was due, in ONE transaction. Returns 'created', 'skipped', 'superseded', 'not_due' or 'failed'.

    The occurrence is CLAIMED first with a conditional update (the next due time we read must still be there), so a second
    tick that gets here after us finds it gone. Anything unexpected raised after the claim rolls the claim back with it: the
    schedule simply stays due and the next tick tries again."""
    stamp = rs.format_ts(now)
    with db.transaction(conn):
        row = conn.execute("SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)).fetchone()
        if row is None or not row["enabled"] or row["next_due_at"] is None or row["next_due_at"] > stamp:
            return "not_due"                                   # paused, resumed or fired by someone else since we looked
        next_due = rs.format_ts(now + dt.timedelta(seconds=row["interval_seconds"]))
        claimed = conn.execute(
            "UPDATE schedules SET next_due_at = ? WHERE schedule_id = ? AND enabled = 1 AND next_due_at = ?",
            (next_due, schedule_id, row["next_due_at"])).rowcount
        if claimed != 1:
            return "superseded"
        if _run_is_active(conn):
            return "skipped"                                   # the occurrence is dropped and the next one is a full interval away
        try:
            run_type, config = _run_config(row)
        except _BadSchedule as exc:
            log.error("schedule %s cannot create a run: %s", schedule_id, exc)
            return "failed"                                    # claim kept: one log line per interval, not per tick
        run_id = runs.create_run_in_tx(conn, run_type, "scheduled", now=now, config=config, schedule_id=schedule_id)
        conn.execute("UPDATE schedules SET last_run_id = ? WHERE schedule_id = ?", (run_id, schedule_id))
        return "created"


def tick(conn: sqlite3.Connection, ctx: service.Context, now: dt.datetime) -> TickResult:
    """Create the runs that are due at `now`. Safe to call from several threads, loops or processes at once."""
    due = [r[0] for r in conn.execute(
        "SELECT schedule_id FROM schedules WHERE enabled = 1 AND next_due_at IS NOT NULL AND next_due_at <= ? "
        "ORDER BY next_due_at, schedule_id", (rs.format_ts(now),))]
    if not due:
        return TickResult()
    try:
        service.sweep(conn, ctx, now)                          # expire stale queued/running runs before deciding about overlap
    except Exception as exc:                                    # noqa: BLE001 - an unexpired stale run only makes us skip
        log.error("expiry before scheduling failed: %s", type(exc).__name__)
    counts = {"created": 0, "skipped": 0, "failed": 0, "superseded": 0, "not_due": 0}
    for schedule_id in due:
        try:
            outcome = _fire(conn, now, schedule_id)
        except Exception as exc:                                # noqa: BLE001 - one schedule must not stop the others
            log.error("schedule %s failed: %s", schedule_id, type(exc).__name__)   # the class only: messages can quote data
            outcome = "failed"
        counts[outcome] += 1
    return TickResult(counts["created"], counts["skipped"], counts["failed"], counts["superseded"])
