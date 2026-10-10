"""Request and response models for /api/schedules (pydantic v2). Strict: no coercion, no extra fields.

Shape only. What a schedule MEANS (interval limits, the configuration checks, the TLS opt-in) is decided in schedules.py.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


# ------------------------------------------------------------------ requests
class ScheduleCreate(_Strict):
    run_type: Literal["filesystem", "tls"]
    interval_seconds: int                                   # strict: a boolean, a float or a string is refused here
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    probe_all_listeners: bool = False                       # TLS only: the explicit opt-in when no ports are listed


class SchedulePatch(_Strict):
    enabled: bool                                           # pause (false) or resume (true); nothing else can be changed


# ------------------------------------------------------------------ responses
class LastRun(BaseModel):
    run_id: str
    run_number: int
    status: str                                             # the run's real lifecycle status, as stored
    queued_at: str
    finished_at: str | None


class ScheduleView(BaseModel):
    schedule_id: str
    run_type: str
    interval_seconds: int
    config: dict[str, Any]
    probe_all_listeners: bool                               # True: a TLS schedule that probes every eligible listener
    enabled: bool
    state: Literal["waiting", "skipping", "paused"]         # paused / enabled and idle / enabled while a run is queued or running
    next_due_at: str | None                                 # null while paused
    created_at: str
    last_run: LastRun | None
    run_count: int


class ScheduleEnvelope(BaseModel):
    schedule: ScheduleView


class ScheduleListEnvelope(BaseModel):
    schedules: list[ScheduleView]
