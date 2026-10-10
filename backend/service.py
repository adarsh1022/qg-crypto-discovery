"""Protocol logic for the agent <-> backend execution flow (framework-independent; routes only call this).

Every operation is ONE transaction opened here (BEGIN IMMEDIATE), inside which it
    1. checks the run exists and, for agent-owned operations, that the caller holds the run's lease,
    2. applies lazy expiry (queue timeout / lost heartbeat / unanswered cancellation) using the request's arrival time,
    3. checks the run is in a state that allows the operation,
    4. calls the existing domain functions (runs.*, fs_ingest.*, run_state.*) to do the work.
No status, ingestion or timeout rule is re-implemented here: this module only sequences them.

Rejections are RETURNED inside the transaction and raised after it commits. That matters: a request that is refused
because the run just expired must not roll back the expiry it triggered. Unexpected errors (database failures, bugs)
are raised inside the transaction and roll everything back.

Time: every decision uses `now`, the request's arrival time (taken before any wait for the write lock). Leases are
measured against `ctx.not_before`, the moment this process started, so a restart does not instantly kill healthy runs.
"""
from __future__ import annotations

import datetime as dt
import math
from dataclasses import dataclass
from typing import Any, Callable

import sqlite3

from . import db, errors, fs_ingest, run_state as rs, runs, tls_ingest
from .errors import ApiError
from .settings import Settings

FS_LIST_KEYS = ("roots", "extensions", "exclude_dir_names", "exclude_paths")
FS_POSITIVE_INT_KEYS = ("max_file_bytes", "max_entries", "max_candidates", "max_certs_per_file")
FS_NONNEGATIVE_INT_KEYS = ("max_depth", "expiring_days")
FS_NUMBER_KEYS = ("time_budget_seconds",)
FS_CONFIG_KEYS = frozenset(FS_LIST_KEYS + FS_POSITIVE_INT_KEYS + FS_NONNEGATIVE_INT_KEYS + FS_NUMBER_KEYS)
# TLS runs probe the TLS services listening on THIS machine. The configuration can only tune limits and NARROW the listeners
# the agent finds (a port list); it can never name a target. The agent's TlsScanConfig is the semantic source of truth.
TLS_CONFIG_KEYS = frozenset({"max_targets", "connect_timeout_seconds", "handshake_timeout_seconds", "time_budget_seconds", "ports"})
TLS_TIMEOUT_MAX = 30
TLS_BUDGET_MAX = 3600
TLS_MAX_TARGETS = 1024
TLS_MAX_PORTS = 256
RUN_TYPES_WITH_AGENT = ("filesystem", "tls")           # the run types an agent can claim
RUN_VIEW_FIELDS = ("run_id", "run_number", "type", "trigger", "schedule_id", "status", "config", "host_id", "queued_at",
                   "started_at", "finished_at", "last_heartbeat_at", "duration_ms", "stop_reason", "cancel_requested",
                   "cancel_requested_at", "record_count", "finding_count", "rejected_count", "error_count", "error_summary",
                   "agent_summary")
MAX_LIST_ENTRIES = 200
MAX_TEXT = 33000
MAX_INT = 10**12


@dataclass(frozen=True)
class Context:
    settings: Settings
    not_before: dt.datetime | None = None          # process start: the floor for lease / queue / cancel timing


@dataclass(frozen=True)
class Claim:
    run: dict
    lease_token: str                               # returned once, to the claimer; only its hash is stored


@dataclass(frozen=True)
class Heartbeat:
    status: str
    cancel_requested: bool


@dataclass(frozen=True)
class Ingested:
    batch: fs_ingest.BatchResult
    status: str
    cancel_requested: bool


def api_view(run: dict, *, with_summary: bool = True) -> dict:
    """A run dictionary from runs.get_run in its public form: column run_trigger is 'trigger', and no lease, ever."""
    out = {name: run[name] for name in RUN_VIEW_FIELDS if name not in ("trigger", "agent_summary")}
    out["trigger"] = run["run_trigger"]
    out["agent_summary"] = run["agent_summary"] if with_summary else None
    return out


# ------------------------------------------------------------------ plumbing
def _transact(conn: sqlite3.Connection, work: Callable[[], Any]) -> Any:
    """Run `work` in one transaction. It may RETURN an ApiError (committing side effects such as expiry) which is then raised."""
    with db.transaction(conn):
        result = work()
    if isinstance(result, ApiError):
        raise result
    return result


def _apply_expiry(conn: sqlite3.Connection, ctx: Context, run_id: str, now: dt.datetime) -> rs.RunState:
    """Apply the run's timeout verdict, if any, through the domain functions. Returns the (possibly new) state."""
    state = runs.load_state(conn, run_id)
    verdict = rs.expiry_verdict(state, now, ctx.settings.timeouts, ctx.not_before)
    if verdict is None:
        return state
    if verdict.kind == rs.QUEUE_TIMEOUT:
        return runs.fail_run_in_tx(conn, run_id, now=now, code="agent_not_connected")
    outcome = "cancelled" if verdict.kind == rs.CANCELLED else "lost"
    return _finalize_in_tx(conn, run_id, now=now, outcome=outcome, agent_lost=verdict.agent_lost)


def _run_type(conn: sqlite3.Connection, run_id: str) -> str:
    return conn.execute("SELECT type FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0]


def _finalize_in_tx(conn: sqlite3.Connection, run_id: str, **kwargs) -> rs.RunState:
    """End a running run through the finalizer of ITS type. Filesystem runs make exactly the call they always did."""
    if _run_type(conn, run_id) == "tls":
        return tls_ingest.finalize_tls_run_in_tx(conn, run_id, **kwargs)
    return fs_ingest.finalize_fs_run_in_tx(conn, run_id, **kwargs)


def _view(conn: sqlite3.Connection, run_id: str) -> dict:
    return runs.get_run(conn, run_id)


def _check_lease(conn: sqlite3.Connection, run_id: str, token: str | None) -> ApiError | None:
    if not runs.lease_matches(runs.get_lease_hash(conn, run_id), token):       # RunNotFound -> 404
        return errors.invalid_lease()
    return None


def _not_running(conn: sqlite3.Connection, run_id: str, state: rs.RunState) -> ApiError | None:
    if state.status == rs.RUNNING:
        return None
    return errors.run_not_running(_view(conn, run_id))


# ------------------------------------------------------------------ run creation and reads
def validate_run_config(run_type: str, config: dict) -> dict:
    """Shape-only validation of the requested configuration. Semantics (absolute paths, ...) stay with the agent's
    ScanConfig, the single source of truth; a configuration the agent rejects ends the run as failed."""
    if run_type == "filesystem":
        if any(key not in FS_CONFIG_KEYS for key in config):
            raise errors.invalid_config({"problem": "unknown_key", "allowed_keys": sorted(FS_CONFIG_KEYS)})
        for key, value in config.items():
            if key in FS_LIST_KEYS:
                ok = (isinstance(value, list) and len(value) <= MAX_LIST_ENTRIES
                      and all(isinstance(x, str) and 0 < len(x) <= MAX_TEXT for x in value))
            elif key in FS_POSITIVE_INT_KEYS:
                ok = isinstance(value, int) and not isinstance(value, bool) and 0 < value <= MAX_INT
            elif key in FS_NONNEGATIVE_INT_KEYS:
                ok = isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_INT
            else:
                ok = (isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
                      and 0 < value <= MAX_INT)
            if not ok:
                raise errors.invalid_config({"field": key, "problem": "wrong_type_or_range"})
    elif run_type == "tls":
        _validate_tls_config(config)
    return config


def _validate_tls_config(config: dict) -> None:
    """Shape-only validation of a TLS run's configuration (the agent's TlsScanConfig has the final say).

    Only the five keys the agent understands are accepted; any other key is refused HERE, at creation, so a run with an
    unknown setting never exists and no agent can claim or probe it. The configuration can tune limits and narrow the
    listeners the agent finds (a port list); it can never name a target.
    """
    if any(key not in TLS_CONFIG_KEYS for key in config):
        raise errors.invalid_config({"problem": "unknown_key", "allowed_keys": sorted(TLS_CONFIG_KEYS)})
    for key, value in config.items():
        if key == "max_targets":
            ok = isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= TLS_MAX_TARGETS
        elif key == "ports":
            ok = (isinstance(value, list) and 1 <= len(value) <= TLS_MAX_PORTS
                  and all(isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535 for p in value))
        else:
            ceiling = TLS_BUDGET_MAX if key == "time_budget_seconds" else TLS_TIMEOUT_MAX
            ok = isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 < value <= ceiling
        if not ok:
            raise errors.invalid_config({"field": key, "problem": "wrong_type_or_range"})


def create_run(conn: sqlite3.Connection, ctx: Context, now: dt.datetime, *, run_type: str, trigger: str,
               schedule_id: str | None, config: dict) -> dict:
    """The public way to start a run: always a MANUAL run. A caller cannot label a run 'scheduled' or attach a schedule to it;
    scheduled runs are created only by the scheduler (backend/schedules.py), which has its own trusted path."""
    if trigger != "manual" or schedule_id is not None:
        raise errors.scheduled_runs_reserved()
    config = validate_run_config(run_type, config)
    try:
        runs.clean_json_object(config)                          # forbidden keys, PEM armor, size, depth
    except ValueError:
        raise errors.invalid_config({"problem": "rejected_content"}) from None

    def work():
        run_id = runs.create_run_in_tx(conn, run_type, "manual", now=now, config=config)
        return _view(conn, run_id)
    return _transact(conn, work)


def get_run(conn: sqlite3.Connection, run_id: str) -> dict:
    run = runs.get_run(conn, run_id)
    if run is None:
        raise errors.run_not_found()
    return run


def list_runs(conn: sqlite3.Connection, *, run_type: str | None, status: str | None, limit: int, offset: int) -> list[dict]:
    return runs.list_runs(conn, run_type=run_type, status=status, limit=limit, offset=offset)


# ------------------------------------------------------------------ claim
def claim_run(conn: sqlite3.Connection, ctx: Context, now: dt.datetime, run_id: str, *, agent_id: str, hostname: str,
              os_name: str | None, agent_version: str | None) -> Claim:
    """queued -> running for exactly one claimant; issues the lease. Everyone else gets run_not_claimable."""
    token, token_hash = runs.generate_lease()

    def work():
        state = _apply_expiry(conn, ctx, run_id, now)                     # RunNotFound -> 404; a stale queued run fails here
        if state.status != rs.QUEUED:
            return errors.run_not_claimable(_view(conn, run_id))
        run_type = _run_type(conn, run_id)
        if run_type not in RUN_TYPES_WITH_AGENT:
            return errors.unsupported_run_type(run_type)
        runs.register_host_in_tx(conn, agent_id, hostname, os_name=os_name, agent_version=agent_version, now=now)
        runs.start_run_in_tx(conn, run_id, now=now, lease_hash=token_hash, host_id=agent_id)
        return _view(conn, run_id)
    return Claim(run=_transact(conn, work), lease_token=token)


# ------------------------------------------------------------------ agent-owned operations
def heartbeat(conn: sqlite3.Connection, ctx: Context, now: dt.datetime, run_id: str, token: str | None) -> Heartbeat:
    def work():
        refused = _check_lease(conn, run_id, token)
        if refused:
            return refused
        state = _apply_expiry(conn, ctx, run_id, now)
        refused = _not_running(conn, run_id, state)
        if refused:
            return refused
        if rs.lease_state(state, now, ctx.settings.timeouts, ctx.not_before) != rs.FRESH:
            return errors.lease_overdue(_view(conn, run_id))              # still running, but only finish is accepted now
        new = runs.heartbeat_run_in_tx(conn, run_id, now=now)
        return Heartbeat(status=new.status, cancel_requested=new.cancel_requested)
    return _transact(conn, work)


def ingest_observations(conn: sqlite3.Connection, ctx: Context, now: dt.datetime, run_id: str, token: str | None,
                        items: list) -> Ingested:
    if len(items) > ctx.settings.max_batch_items:
        raise errors.batch_too_large(ctx.settings.max_batch_items)

    def work():
        refused = _check_lease(conn, run_id, token)
        if refused:
            return refused
        state = _apply_expiry(conn, ctx, run_id, now)
        refused = _not_running(conn, run_id, state)
        if refused:
            return refused
        if rs.lease_state(state, now, ctx.settings.timeouts, ctx.not_before) != rs.FRESH:
            return errors.lease_overdue(_view(conn, run_id))
        try:
            ingest = tls_ingest.ingest_tls_batch_in_tx if _run_type(conn, run_id) == "tls" else fs_ingest.ingest_fs_batch_in_tx
            batch = ingest(conn, run_id, items, now=now)                              # idempotent; conflicts recorded
        except fs_ingest.BatchRejected:
            return errors.bad_batch_item()                                            # nothing was written
        current = runs.load_state(conn, run_id)
        return Ingested(batch=batch, status=current.status, cancel_requested=current.cancel_requested)
    return _transact(conn, work)


def finish_run(conn: sqlite3.Connection, ctx: Context, now: dt.datetime, run_id: str, token: str | None, *, outcome: str,
               summary: dict | None, fatal_code: str | None) -> dict:
    """The agent says how its part ended; the backend decides the run's final status from the stored evidence."""
    def work():
        refused = _check_lease(conn, run_id, token)
        if refused:
            return refused
        state = _apply_expiry(conn, ctx, run_id, now)
        if state.status != rs.RUNNING:
            view = _view(conn, run_id)
            return errors.run_already_finished(api_view(view)) if state.status in rs.TERMINAL else errors.run_not_running(view)
        # fresh and overdue both qualify: the overdue window exists precisely so a healthy agent can still finish
        _finalize_in_tx(conn, run_id, now=now, outcome=outcome, summary=summary, fatal_code=fatal_code)
        return _view(conn, run_id)
    return _transact(conn, work)


# ------------------------------------------------------------------ cancellation (no lease: anyone who can reach the API)
def cancel_run(conn: sqlite3.Connection, ctx: Context, now: dt.datetime, run_id: str) -> dict:
    """queued -> failed(cancelled); running -> flagged so the agent stops (and a silent agent is cut off after the grace).
    Repeating a cancel is a no-op; cancelling a run that finished for another reason is refused."""
    def work():
        state = _apply_expiry(conn, ctx, run_id, now)
        if state.status in (rs.QUEUED, rs.RUNNING):
            runs.request_cancel_in_tx(conn, run_id, now=now)
            return _view(conn, run_id)
        view = _view(conn, run_id)
        if view["cancel_requested"] or view["stop_reason"] == "cancelled":
            return view
        return errors.run_not_cancellable(view)
    return _transact(conn, work)


# ------------------------------------------------------------------ recovery
def sweep(conn: sqlite3.Connection, ctx: Context, now: dt.datetime) -> int:
    """Expire every stale queued/running run (one transaction each). Idempotent; returns how many runs changed."""
    run_ids = [r[0] for r in conn.execute("SELECT run_id FROM runs WHERE status IN ('queued', 'running') ORDER BY run_number")]
    changed = 0
    for run_id in run_ids:
        def work(run_id=run_id):
            before = runs.load_state(conn, run_id).status
            return _apply_expiry(conn, ctx, run_id, now).status != before
        changed += bool(_transact(conn, work))
    return changed
