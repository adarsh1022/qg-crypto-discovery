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
             re-sent with contradicting content, a count mismatch, or the agent was lost
  completed  everything else: a clean, fully covered scan (finding nothing is still completed)
The reasons are fixed codes with counts, never OS messages, paths or free text from the agent.
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

OUTCOMES = ("finished", "failed", "lost")     # how the agent's part ended
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
    fatal_code: str | None = None           # short code such as 'capture_unavailable'

    def __post_init__(self):
        if self.outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {OUTCOMES}")
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
    return dataclasses.replace(run, last_heartbeat_at=format_ts(now))


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
        return dataclasses.replace(run, cancel_requested=True)
    raise InvalidTransition(f"cannot cancel a {run.status} run")


def decide_outcome(counts: Counts, report: AgentReport) -> tuple[str, tuple[str, ...]]:
    """(final status, reason codes). Pure. See the module docstring for the rules."""
    reasons: list[str] = []
    if report.outcome == "failed":
        code = report.fatal_code if _CODE.fullmatch(report.fatal_code or "") else "agent_failed"
        return FAILED, (code,)
    if report.outcome == "lost":
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

    no_usable_data = counts.records == 0 and (not report.coverage_started or counts.rejected > 0)
    if no_usable_data:
        return FAILED, tuple(["no_usable_data"] + reasons)
    return (PARTIAL, tuple(reasons)) if reasons else (COMPLETED, ())


def finish(run: RunState, now: dt.datetime, counts: Counts, report: AgentReport) -> RunState:
    """End a running run; the final status comes from decide_outcome."""
    status, reasons = decide_outcome(counts, report)
    _require(run, status)
    if report.outcome == "lost":
        stop_reason = "agent_lost"
    else:
        stop_reason = report.stop_reason if _CODE.fullmatch(report.stop_reason or "") else None
    if status == FAILED and stop_reason is None:
        stop_reason = reasons[0]
    return dataclasses.replace(run, status=status, stop_reason=stop_reason,
                               error_summary=", ".join(reasons) if reasons else None,
                               **_count_fields(counts), **_finish_fields(run, now))


def expire(run: RunState, now: dt.datetime, *, queue_timeout_s: float, heartbeat_timeout_s: float) -> RunState | None:
    """Apply timeouts: a run nobody claimed fails; a running run that went silent ends as lost.

    Returns the new state, or None if nothing has expired.
    """
    if run.status == QUEUED:
        if now - parse_ts(run.queued_at) > dt.timedelta(seconds=queue_timeout_s):
            return fail(run, now, "agent_not_connected")
        return None
    if run.status == RUNNING:
        last = parse_ts(run.last_heartbeat_at or run.started_at)
        if now - last > dt.timedelta(seconds=heartbeat_timeout_s):
            counts = Counts(run.record_count, run.finding_count, run.rejected_count, run.error_count)
            return finish(run, now, counts, AgentReport(outcome="lost", coverage_started=run.record_count > 0))
    return None
