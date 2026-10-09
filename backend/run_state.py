"""Run lifecycle as pure functions: no I/O, no clock, no database.

    queued --start--> running --finish--> completed | partial | failed
       \\--fail (never claimed / cancelled before start)--> failed

Every function takes the current RunState and `now` and returns a NEW RunState, or raises
InvalidTransition. The caller (a later phase) loads a row, calls a function, and stores the result;
the database repeats the status rules as CHECK constraints and a trigger (see 0001_initial.sql).

How a run ends (decide_outcome), from the backend's own counts plus what the agent reported:
  failed     the agent reported a fatal failure, or there is no usable data (nothing was scanned and
             nothing was accepted, or every record was rejected, or the agent vanished before sending any)
  partial    usable data, but discovery coverage is incomplete or the evidence is contested: stopped by a limit or by
             cancellation, a root that was not scanned, a truncated certificate bundle, a file or directory that
             could not be read (access_denied / read_error / listdir / stat), a rejected record, a sequence number
             re-sent with contradicting content, a count mismatch, or the agent was lost.
             A cancelled run is partial even when nothing was stored, whether the backend enforced the cancellation or
             the agent stopped on request after one was recorded (failed only if every record it sent was rejected).
  completed  everything else: a clean, fully covered scan (finding nothing is still completed)
The reasons are fixed codes with counts, never OS messages, paths or free text from the agent.

Lease and timeouts (all decisions are made at the request's arrival time, `now`, so they are deterministic):

    age = now - max(last heartbeat, backend start)            # the backend-start floor protects healthy agents across a restart
    age <= heartbeat_s                          fresh    every agent call is accepted
    heartbeat_s < age <= heartbeat_s + grace    overdue  still running; ONLY finish is accepted (the finish race window)
    age >  heartbeat_s + grace                  lost     the backend ends the run (partial with data, otherwise failed)

The window is `finish_grace_s` (seconds, small), not a second timeout: a late heartbeat or batch is refused in it, and
the run is lost once it has passed. Queued runs fail after `queue_s`. A cancellation request that the agent has not
answered within `cancel_grace_s` ends the run as partial/cancelled.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import re
from dataclasses import dataclass

QUEUED, RUNNING, COMPLETED, PARTIAL, FAILED = "queued", "running", "completed", "partial", "failed"
STATUSES = (QUEUED, RUNNING, COMPLETED, PARTIAL, FAILED)
TERMINAL = frozenset({COMPLETED, PARTIAL, FAILED})
TRANSITIONS = {
    QUEUED: frozenset({RUNNING, FAILED}),
    RUNNING: frozenset({COMPLETED, PARTIAL, FAILED}),
    COMPLETED: frozenset(),
    PARTIAL: frozenset(),
    FAILED: frozenset(),
}

OUTCOMES = ("finished", "failed", "lost", "cancelled")   # how the agent's part ended ("lost", "cancelled": backend-decided)
CLEAN_STOP = "completed"                      # Scan.summary["stop_reason"] of a scan that ran to the end

_CODE = re.compile(r"[a-z0-9_]{1,40}")                 # always used with fullmatch: "$" would accept a trailing newline
_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class InvalidTransition(ValueError):
    pass


# ------------------------------------------------------------------ time
def format_ts(moment: dt.datetime) -> str:
    """Fixed-width UTC timestamp with milliseconds (sorts lexicographically)."""
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    utc = moment.astimezone(dt.timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def parse_ts(text: str) -> dt.datetime:
    return dt.datetime.strptime(text, _TS_FORMAT).replace(tzinfo=dt.timezone.utc)


def duration_ms(started_at: str, finished_at: str) -> int:
    """Whole milliseconds between two run timestamps; never negative (a backwards clock gives 0)."""
    delta = parse_ts(finished_at) - parse_ts(started_at)
    return max(0, delta // dt.timedelta(milliseconds=1))


# ------------------------------------------------------------------ data
@dataclass(frozen=True)
class RunState:
    status: str
    queued_at: str
    started_at: str | None = None
    finished_at: str | None = None
    last_heartbeat_at: str | None = None
    duration_ms: int | None = None
    stop_reason: str | None = None
    cancel_requested: bool = False
    cancel_requested_at: str | None = None
    record_count: int = 0
    finding_count: int = 0
    rejected_count: int = 0
    error_count: int = 0
    error_summary: str | None = None

    def to_columns(self) -> dict:
        """The runs-table columns this state owns (booleans as 0/1)."""
        columns = dataclasses.asdict(self)
        columns["cancel_requested"] = int(self.cancel_requested)
        return columns

    @classmethod
    def from_row(cls, row) -> "RunState":
        values = {f.name: row[f.name] for f in dataclasses.fields(cls)}
        values["cancel_requested"] = bool(values["cancel_requested"])
        return cls(**values)


@dataclass(frozen=True)
class Counts:
    """Recomputed by the backend from the rows it stored (never the agent's own totals)."""
    records: int = 0        # accepted records
    findings: int = 0       # accepted records that are findings (certificate sightings / TLS connections)
    rejected: int = 0       # records the backend refused
    errors: int = 0         # file-level read failures: access_denied + read_error

    def __post_init__(self):
        for f in dataclasses.fields(self):
            value = getattr(self, f.name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{f.name} must be a non-negative integer")


@dataclass(frozen=True)
class AgentReport:
    """What the agent said about how its part ended (from Scan.summary, mapped by the ingest layer)."""
    outcome: str                            # 'finished' | 'failed' | 'lost'
    stop_reason: str | None = None          # 'completed' for a clean scan; otherwise the reason it stopped
    coverage_started: bool = False          # at least one root was actually scanned / capture began
    roots_not_scanned: int = 0              # roots not reached, unreadable, missing, ... (not 'overlap')
    truncated_files: int = 0                # certificate bundles cut off by the per-file limit
    count_mismatch: bool = False            # agent's own totals disagree with what the backend stored
    seq_conflicts: int = 0                  # sequence numbers re-sent with content that contradicts what was stored
    agent_lost: bool = False                # for outcome "cancelled": the agent had also stopped heartbeating
    cancel_requested: bool = False          # the BACKEND's record that this run was asked to stop (never the agent's claim)
    fatal_code: str | None = None           # short code such as 'capture_unavailable'

    def __post_init__(self):
        if self.outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {OUTCOMES}")
        for name in ("agent_lost", "cancel_requested"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a boolean")
        for name in ("roots_not_scanned", "truncated_files", "seq_conflicts"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


# ------------------------------------------------------------------ transitions
def can_transition(src: str, dst: str) -> bool:
    return dst in TRANSITIONS.get(src, ())


def _require(run: RunState, dst: str) -> None:
    if run.status not in TRANSITIONS:
        raise InvalidTransition(f"unknown status {run.status!r}")
    if not can_transition(run.status, dst):
        raise InvalidTransition(f"cannot go from {run.status} to {dst}")


def new_run(now: dt.datetime) -> RunState:
    return RunState(status=QUEUED, queued_at=format_ts(now))


def start(run: RunState, now: dt.datetime) -> RunState:
    """The agent claimed the run."""
    _require(run, RUNNING)
    stamp = format_ts(now)
    return dataclasses.replace(run, status=RUNNING, started_at=stamp, last_heartbeat_at=stamp)


def heartbeat(run: RunState, now: dt.datetime) -> RunState:
    if run.status != RUNNING:
        raise InvalidTransition(f"cannot heartbeat a {run.status} run")
    stamp = format_ts(now)
    if run.last_heartbeat_at is not None and stamp < run.last_heartbeat_at:
        stamp = run.last_heartbeat_at            # requests are timed on arrival and may commit out of order: never go back
    return dataclasses.replace(run, last_heartbeat_at=stamp)


def update_counts(run: RunState, counts: Counts) -> RunState:
    """Progress counters while running (recomputed from stored rows by the caller)."""
    if run.status != RUNNING:
        raise InvalidTransition(f"cannot update counts of a {run.status} run")
    return dataclasses.replace(run, **_count_fields(counts))


def _count_fields(counts: Counts) -> dict:
    return dict(record_count=counts.records, finding_count=counts.findings,
                rejected_count=counts.rejected, error_count=counts.errors)


def _finish_fields(run: RunState, now: dt.datetime) -> dict:
    """finished_at never precedes started_at, so a backwards clock cannot produce an invalid row."""
    finished = format_ts(now)
    if run.started_at is not None and finished < run.started_at:
        finished = run.started_at
    duration = duration_ms(run.started_at, finished) if run.started_at is not None else None
    return dict(finished_at=finished, duration_ms=duration)


def fail(run: RunState, now: dt.datetime, code: str, counts: Counts | None = None) -> RunState:
    """Unconditional failure of a queued or running run (never claimed, cancelled before start, ...)."""
    _require(run, FAILED)
    code = code if _CODE.fullmatch(code or "") else "failed"
    fields = _count_fields(counts) if counts is not None else {}
    return dataclasses.replace(run, status=FAILED, stop_reason=code, error_summary=code,
                               **_finish_fields(run, now), **fields)


def request_cancel(run: RunState, now: dt.datetime) -> RunState:
    """Queued runs fail immediately; running runs are flagged and the agent stops at its next heartbeat."""
    if run.status == QUEUED:
        return fail(run, now, "cancelled")
    if run.status == RUNNING:
        if run.cancel_requested:
            return run                           # idempotent: the first request (and its timestamp) stands
        return dataclasses.replace(run, cancel_requested=True, cancel_requested_at=format_ts(now))
    raise InvalidTransition(f"cannot cancel a {run.status} run")


def cancelled_on_request(report: AgentReport) -> bool:
    """Did this run end because it was cancelled? True for the backend's own enforcement ("cancelled") and for an agent that
    stopped with stop_reason "cancelled" AFTER the backend had recorded a cancel request. An agent's say-so alone does not
    count: a scan that merely claims to be cancelled gains nothing, so a real failure cannot be dressed up as one."""
    return report.outcome == "cancelled" or (report.outcome == "finished" and report.stop_reason == "cancelled"
                                             and report.cancel_requested)


def decide_outcome(counts: Counts, report: AgentReport) -> tuple[str, tuple[str, ...]]:
    """(final status, reason codes). Pure. See the module docstring for the rules."""
    reasons: list[str] = []
    if report.outcome == "failed":
        code = report.fatal_code if _CODE.fullmatch(report.fatal_code or "") else "agent_failed"
        return FAILED, (code,)
    if report.outcome == "lost":
        reasons.append("agent_lost")
    elif report.outcome == "cancelled":
        reasons.append("stopped_cancelled")
        if report.agent_lost:
            reasons.append("agent_lost")
    elif report.stop_reason is None:
        reasons.append("stop_reason_missing")
    elif report.stop_reason != CLEAN_STOP:
        reasons.append(f"stopped_{report.stop_reason}" if _CODE.fullmatch(report.stop_reason) else "stopped_unknown")
    for code, number in (("roots_not_scanned", report.roots_not_scanned),
                         ("bundles_truncated", report.truncated_files),
                         ("file_errors", counts.errors),
                         ("records_rejected", counts.rejected),
                         ("seq_conflicts", report.seq_conflicts)):
        if number:
            reasons.append(f"{code}:{number}")
    if report.count_mismatch:
        reasons.append("count_mismatch")

    started = report.coverage_started or cancelled_on_request(report)          # a run that was told to stop did start
    no_usable_data = counts.records == 0 and (not started or counts.rejected > 0)
    if no_usable_data:
        return FAILED, tuple(["no_usable_data"] + reasons)
    return (PARTIAL, tuple(reasons)) if reasons else (COMPLETED, ())


def finish(run: RunState, now: dt.datetime, counts: Counts, report: AgentReport) -> RunState:
    """End a running run; the final status comes from decide_outcome."""
    status, reasons = decide_outcome(counts, report)
    _require(run, status)
    if report.outcome == "lost":
        stop_reason = "agent_lost"
    elif report.outcome == "cancelled":
        stop_reason = "cancelled"
    else:
        stop_reason = report.stop_reason if _CODE.fullmatch(report.stop_reason or "") else None
    if status == FAILED and stop_reason is None:
        stop_reason = reasons[0]
    return dataclasses.replace(run, status=status, stop_reason=stop_reason,
                               error_summary=", ".join(reasons) if reasons else None,
                               **_count_fields(counts), **_finish_fields(run, now))


@dataclass(frozen=True)
class Timeouts:
    queue_s: float = 120.0                 # a queued run nobody claimed fails after this long
    heartbeat_s: float = 90.0              # a running run needs a sign of life at least this often
    finish_grace_s: float = 5.0            # race window after heartbeat_s in which only `finish` is still accepted
    cancel_grace_s: float | None = 60.0    # a cancellation the agent has not answered within this long is enforced

    def __post_init__(self):
        for name in ("queue_s", "heartbeat_s"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value < float("inf"):
                raise ValueError(f"{name} must be a positive finite number")
        for name, allow_none in (("finish_grace_s", False), ("cancel_grace_s", True)):
            value = getattr(self, name)
            if value is None and allow_none:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value < float("inf"):
                raise ValueError(f"{name} must be a non-negative finite number")


FRESH, OVERDUE, LOST = "fresh", "overdue", "lost"
QUEUE_TIMEOUT, CANCELLED = "queue_timeout", "cancelled"      # (LOST doubles as a verdict kind)


@dataclass(frozen=True)
class Verdict:
    """What expiry decides for a run: `kind` is QUEUE_TIMEOUT, LOST or CANCELLED."""
    kind: str
    agent_lost: bool = False               # CANCELLED only: the heartbeat had also gone stale


def _floor(moment: dt.datetime, not_before: dt.datetime | None) -> dt.datetime:
    return moment if not_before is None or moment >= not_before else not_before


def lease_state(run: RunState, now: dt.datetime, timeouts: Timeouts, not_before: dt.datetime | None = None) -> str:
    """FRESH, OVERDUE or LOST for a running run (see the module docstring for the exact boundaries)."""
    if run.status != RUNNING:
        raise InvalidTransition(f"a {run.status} run has no lease to assess")
    age = now - _floor(parse_ts(run.last_heartbeat_at or run.started_at), not_before)
    if age <= dt.timedelta(seconds=timeouts.heartbeat_s):
        return FRESH
    if age <= dt.timedelta(seconds=timeouts.heartbeat_s + timeouts.finish_grace_s):
        return OVERDUE
    return LOST


def expiry_verdict(run: RunState, now: dt.datetime, timeouts: Timeouts, not_before: dt.datetime | None = None) -> Verdict | None:
    """Has this run run out of time? None if not. Pure: the caller applies the verdict (so 2b's finalization is reused)."""
    if run.status == QUEUED:
        age = now - _floor(parse_ts(run.queued_at), not_before)
        return Verdict(QUEUE_TIMEOUT) if age > dt.timedelta(seconds=timeouts.queue_s) else None
    if run.status != RUNNING:
        return None
    heartbeat_lost = lease_state(run, now, timeouts, not_before) == LOST
    if run.cancel_requested:
        if heartbeat_lost:
            return Verdict(CANCELLED, agent_lost=True)
        if timeouts.cancel_grace_s is not None and run.cancel_requested_at is not None:
            waited = now - _floor(parse_ts(run.cancel_requested_at), not_before)
            if waited > dt.timedelta(seconds=timeouts.cancel_grace_s):
                return Verdict(CANCELLED)
        return None
    return Verdict(LOST) if heartbeat_lost else None


def expire(run: RunState, now: dt.datetime, *, queue_timeout_s: float, heartbeat_timeout_s: float,
           finish_grace_s: float = 0.0, cancel_grace_s: float | None = None,
           not_before: dt.datetime | None = None) -> RunState | None:
    """Apply timeouts to a RunState using only its own counters: a run nobody claimed fails; a silent running run ends
    as lost (or cancelled, if it was asked to stop). Returns the new state, or None if nothing has expired.

    The filesystem service does not use this: it applies `expiry_verdict` through 2b's finalization so that reasons
    derived from stored rows (sequence conflicts, ...) are included. This is the same decision for callers that only
    have the state.
    """
    verdict = expiry_verdict(run, now, Timeouts(queue_timeout_s, heartbeat_timeout_s, finish_grace_s, cancel_grace_s), not_before)
    if verdict is None:
        return None
    if verdict.kind == QUEUE_TIMEOUT:
        return fail(run, now, "agent_not_connected")
    counts = Counts(run.record_count, run.finding_count, run.rejected_count, run.error_count)
    if verdict.kind == CANCELLED:
        return finish(run, now, counts, AgentReport(outcome="cancelled", agent_lost=verdict.agent_lost))
    return finish(run, now, counts, AgentReport(outcome="lost", coverage_started=run.record_count > 0))
