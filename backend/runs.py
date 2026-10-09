"""Run and host persistence (framework-independent). Status rules live in run_state.py; this module
only loads a run, applies one pure transition, and stores the result.

Transaction ownership is explicit, never implicit:

* Every state-changing operation exists twice. `name_in_tx(conn, ...)` does the work inside a transaction the CALLER
  has opened (it refuses to run without one: db.require_transaction). `name(conn, ...)` is the convenience wrapper that
  opens `db.transaction` (BEGIN IMMEDIATE), calls `name_in_tx`, and commits or rolls back. Wrappers are never called
  from inside another transaction (SQLite would refuse to nest them), so a service that needs several steps to be one
  atomic unit opens the transaction itself and calls the `_in_tx` variants.
* Concurrent claimers are serialised by BEGIN IMMEDIATE; the second one finds the run already running and gets
  InvalidTransition.

Lease: a run is owned by whoever holds the claim token. Only its SHA-256 is stored (runs.lease_hash); the plaintext is
returned once to the claimer and is never stored or logged.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import uuid
from typing import Any

from . import run_state as rs
from .db import require_transaction, transaction
from .fs_record import canonical_json
from .safety import has_pem_armor, is_raw_material_name, sanitize_text

RUN_TYPES = ("filesystem", "tls")
TRIGGERS = ("manual", "scheduled")
MAX_CONFIG_BYTES = 64 * 1024
MAX_CONFIG_DEPTH = 4
_STATE_COLUMNS = tuple(rs.RunState.__dataclass_fields__)


class RunNotFound(LookupError):
    pass


class UnknownHost(LookupError):
    pass


class WrongRunType(ValueError):
    pass


# ------------------------------------------------------------------ lease
_TOKEN = re.compile(r"[0-9a-f]{32}")


def generate_lease() -> tuple[str, str]:
    """(token, token_hash): a fresh 128-bit claim token and the SHA-256 that is stored in its place."""
    token = secrets.token_hex(16)
    return token, hash_lease(token)


def hash_lease(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def lease_matches(stored_hash: str | None, token: Any) -> bool:
    """True iff `token` is the token whose hash is stored. Constant-time; malformed or missing input never matches."""
    if not isinstance(stored_hash, str) or not isinstance(token, str) or not _TOKEN.fullmatch(token):
        return False
    return hmac.compare_digest(stored_hash, hash_lease(token))


def get_lease_hash(conn: sqlite3.Connection, run_id: str) -> str | None:
    row = conn.execute("SELECT lease_hash FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise RunNotFound(run_id)
    return row[0]


# ------------------------------------------------------------------ JSON configuration
def clean_json_object(value: Any, *, what: str = "config") -> str:
    """Validate a small JSON-like dict and return its canonical text.

    Keys must be plain names (never raw-material names), strings must not carry PEM armor, and the whole
    value is size- and depth-limited. Used for run configuration; nothing else is accepted.
    """
    def walk(item: Any, depth: int) -> Any:
        if depth > MAX_CONFIG_DEPTH:
            raise ValueError(f"{what} is nested too deeply")
        if isinstance(item, dict):
            out = {}
            for key, val in item.items():
                if not isinstance(key, str) or is_raw_material_name(key):
                    raise ValueError(f"{what} contains a forbidden key")
                out[sanitize_text(key)] = walk(val, depth + 1)
            return out
        if isinstance(item, (list, tuple)):
            return [walk(v, depth + 1) for v in item]
        if isinstance(item, str):
            text = sanitize_text(item)
            if has_pem_armor(text):
                raise ValueError(f"{what} contains PEM armor")
            return text
        if item is None or isinstance(item, (bool, int)):
            return item
        if isinstance(item, float) and item == item and item not in (float("inf"), float("-inf")):
            return item
        raise ValueError(f"{what} contains an unsupported value")

    if not isinstance(value, dict):
        raise ValueError(f"{what} must be an object")
    text = canonical_json(walk(value, 0))
    if len(text) > MAX_CONFIG_BYTES:
        raise ValueError(f"{what} is too large")
    return text


# ------------------------------------------------------------------ hosts
def register_host(conn: sqlite3.Connection, host_id: str, hostname: str, *, os_name: str | None = None,
                  agent_version: str | None = None, now: dt.datetime) -> None:
    """Insert or refresh a host (first_seen_at is kept). Phase 1 records carry no host data, so the caller supplies it."""
    with transaction(conn):
        register_host_in_tx(conn, host_id, hostname, os_name=os_name, agent_version=agent_version, now=now)


def register_host_in_tx(conn: sqlite3.Connection, host_id: str, hostname: str, *, os_name: str | None = None,
                        agent_version: str | None = None, now: dt.datetime) -> None:
    require_transaction(conn)
    values = {"host_id": host_id, "hostname": hostname, "os": os_name, "agent_version": agent_version}
    for name, val in values.items():
        if val is not None and (not isinstance(val, str) or len(val) > 255 or has_pem_armor(val)):
            raise ValueError(f"invalid {name}")
    if not host_id or not hostname:
        raise ValueError("host_id and hostname are required")
    stamp = rs.format_ts(now)
    conn.execute(
        "INSERT INTO hosts (host_id, hostname, os, agent_version, first_seen_at, last_seen_at) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (host_id) DO UPDATE SET hostname = excluded.hostname, os = excluded.os, "
        "agent_version = excluded.agent_version, last_seen_at = excluded.last_seen_at",
        (sanitize_text(host_id), sanitize_text(hostname), None if os_name is None else sanitize_text(os_name),
         None if agent_version is None else sanitize_text(agent_version), stamp, stamp))


# ------------------------------------------------------------------ load / save
def load_state(conn: sqlite3.Connection, run_id: str) -> rs.RunState:
    row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise RunNotFound(run_id)
    return rs.RunState.from_row(row)


def save_state(conn: sqlite3.Connection, run_id: str, new: rs.RunState, *, expected_status: str, **extra: Any) -> None:
    """Store `new` only if the run is still in `expected_status` (guards against a concurrent change).

    `extra` may carry additional run columns written in the same statement (host_id, agent_summary_json).
    """
    columns = new.to_columns()
    columns.update(extra)
    assignments = ", ".join(f"{name} = ?" for name in columns)          # names come from RunState / this module only
    cursor = conn.execute(f"UPDATE runs SET {assignments} WHERE run_id = ? AND status = ?",
                          (*columns.values(), run_id, expected_status))
    if cursor.rowcount != 1:
        raise rs.InvalidTransition("the run changed while it was being updated")


def get_run(conn: sqlite3.Connection, run_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    return None if row is None else _run_dict(row)


def list_runs(conn: sqlite3.Connection, *, run_type: str | None = None, status: str | None = None,
              limit: int = 100, offset: int = 0) -> list[dict]:
    """Newest first. Filters are optional and parameterised."""
    if run_type is not None and run_type not in RUN_TYPES:
        raise ValueError("unknown run type")
    if status is not None and status not in rs.STATUSES:
        raise ValueError("unknown status")
    limit, offset = _page(limit, offset)
    rows = conn.execute(
        "SELECT * FROM runs WHERE (?1 IS NULL OR type = ?1) AND (?2 IS NULL OR status = ?2) "
        "ORDER BY run_number DESC LIMIT ?3 OFFSET ?4", (run_type, status, limit, offset)).fetchall()
    return [_run_dict(r) for r in rows]


def _page(limit: int, offset: int) -> tuple[int, int]:
    for value in (limit, offset):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("limit and offset must be non-negative integers")
    return min(limit, 1000), offset


def _run_dict(row: sqlite3.Row) -> dict:
    out = dict(row)
    out.pop("lease_hash", None)                       # the lease is never part of any view of a run
    out["config"] = json.loads(out.pop("config_json"))
    summary = out.pop("agent_summary_json")
    out["agent_summary"] = None if summary is None else json.loads(summary)
    out["cancel_requested"] = bool(out["cancel_requested"])
    return out


# ------------------------------------------------------------------ lifecycle
def create_run(conn: sqlite3.Connection, run_type: str, trigger: str, *, now: dt.datetime,
               config: dict | None = None, schedule_id: str | None = None, run_id: str | None = None) -> str:
    """Create a queued run and return its id."""
    config_json = _validated_new_run(run_type, trigger, config)       # reject bad input before taking the write lock
    with transaction(conn):
        return create_run_in_tx(conn, run_type, trigger, now=now, config=config, schedule_id=schedule_id,
                                run_id=run_id, _config_json=config_json)


def _validated_new_run(run_type: str, trigger: str, config: dict | None) -> str:
    if run_type not in RUN_TYPES or trigger not in TRIGGERS:
        raise ValueError("unknown run type or trigger")
    return clean_json_object({} if config is None else config)


def create_run_in_tx(conn: sqlite3.Connection, run_type: str, trigger: str, *, now: dt.datetime,
                     config: dict | None = None, schedule_id: str | None = None, run_id: str | None = None,
                     _config_json: str | None = None) -> str:
    require_transaction(conn)
    config_json = _config_json if _config_json is not None else _validated_new_run(run_type, trigger, config)
    run_id = run_id or uuid.uuid4().hex
    state = rs.new_run(now)
    number = conn.execute("SELECT COALESCE(MAX(run_number), 0) + 1 FROM runs").fetchone()[0]
    conn.execute(
        "INSERT INTO runs (run_id, run_number, type, run_trigger, schedule_id, status, config_json, queued_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (run_id, number, run_type, trigger, schedule_id, state.status, config_json, state.queued_at))
    return run_id


def start_run(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime, host_id: str | None = None,
              lease_hash: str | None = None) -> rs.RunState:
    """queued -> running (the agent claimed the run).

    A run cannot be running without an owner. Callers that hand the claim to an agent use `start_run_in_tx` with the
    hash of the token they return; when none is given here (tests, tools that never present the lease again) a fresh
    random lease is created and its token is discarded.
    """
    with transaction(conn):
        return start_run_in_tx(conn, run_id, now=now, host_id=host_id,
                               lease_hash=lease_hash if lease_hash is not None else generate_lease()[1])


def start_run_in_tx(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime, lease_hash: str,
                    host_id: str | None = None) -> rs.RunState:
    require_transaction(conn)
    if host_id is not None and conn.execute("SELECT 1 FROM hosts WHERE host_id = ?", (host_id,)).fetchone() is None:
        raise UnknownHost(host_id)
    current = load_state(conn, run_id)
    started = rs.start(current, now)
    extra: dict[str, Any] = {"lease_hash": lease_hash}
    if host_id is not None:
        extra["host_id"] = host_id
    save_state(conn, run_id, started, expected_status=current.status, **extra)
    return started


def heartbeat_run_in_tx(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime) -> rs.RunState:
    """Record a sign of life (never moves the heartbeat backwards). Whether the lease is still valid is decided by the caller."""
    require_transaction(conn)
    current = load_state(conn, run_id)
    new = rs.heartbeat(current, now)
    if new != current:
        save_state(conn, run_id, new, expected_status=current.status)
    return new


def request_cancel(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime) -> rs.RunState:
    """Queued runs fail as 'cancelled'; running runs are flagged so the agent stops and reports a partial result."""
    with transaction(conn):
        return request_cancel_in_tx(conn, run_id, now=now)


def request_cancel_in_tx(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime) -> rs.RunState:
    require_transaction(conn)
    current = load_state(conn, run_id)
    new = rs.request_cancel(current, now)
    if new != current:                                   # a repeated request changes nothing
        save_state(conn, run_id, new, expected_status=current.status)
    return new


def fail_run(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime, code: str) -> rs.RunState:
    """Fail a queued or running run outright (never claimed, backend-side error, ...)."""
    with transaction(conn):
        return fail_run_in_tx(conn, run_id, now=now, code=code)


def fail_run_in_tx(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime, code: str) -> rs.RunState:
    require_transaction(conn)
    current = load_state(conn, run_id)
    new = rs.fail(current, now, code)
    save_state(conn, run_id, new, expected_status=current.status)
    return new
