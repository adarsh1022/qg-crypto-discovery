"""Request and response models for the HTTP API (pydantic v2). Strict: no coercion, no extra fields.

Validation here is about shape. Anything about the meaning of a record, a summary or a configuration is decided by the
domain code (fs_record, fs_ingest, service.validate_run_config), not repeated in these models.
"""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import service
from .safety import has_pem_armor

_AGENT_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
_SCHEDULE_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_FATAL_CODE = re.compile(r"[a-z0-9_]{1,40}")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


# ------------------------------------------------------------------ requests
class CreateRunRequest(_Strict):
    type: Literal["filesystem", "tls"]
    trigger: Literal["manual", "scheduled"] = "manual"
    schedule_id: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("schedule_id")
    @classmethod
    def _schedule_id(cls, value: str | None) -> str | None:
        if value is not None and not _SCHEDULE_ID.fullmatch(value):
            raise ValueError("bad schedule id")
        return value


class ClaimRequest(_Strict):
    agent_id: str
    hostname: str = Field(min_length=1, max_length=255)
    os: str | None = Field(default=None, max_length=255)
    agent_version: str | None = Field(default=None, max_length=64)

    @field_validator("agent_id")
    @classmethod
    def _agent_id(cls, value: str) -> str:
        if not _AGENT_ID.fullmatch(value):
            raise ValueError("bad agent id")
        return value

    @field_validator("hostname", "os", "agent_version")
    @classmethod
    def _no_armor(cls, value: str | None) -> str | None:
        if value is not None and has_pem_armor(value):
            raise ValueError("not acceptable")
        return value


class ObservationsRequest(_Strict):
    items: list[list[Any]]                              # [seq, record] pairs; their meaning is the ingestion layer's business


class FinishRequest(_Strict):
    outcome: Literal["finished", "failed"]              # the backend alone decides 'lost' / 'cancelled' and the final status
    summary: dict[str, Any] | None = None
    fatal_code: str | None = None

    @field_validator("fatal_code")
    @classmethod
    def _fatal_code(cls, value: str | None) -> str | None:
        if value is not None and not _FATAL_CODE.fullmatch(value):
            raise ValueError("bad code")
        return value


# ------------------------------------------------------------------ responses
class RunView(BaseModel):
    run_id: str
    run_number: int
    type: str
    trigger: str
    schedule_id: str | None
    status: str
    config: dict[str, Any]
    host_id: str | None
    queued_at: str
    started_at: str | None
    finished_at: str | None
    last_heartbeat_at: str | None
    duration_ms: int | None
    stop_reason: str | None
    cancel_requested: bool
    cancel_requested_at: str | None
    record_count: int
    finding_count: int
    rejected_count: int
    error_count: int
    error_summary: str | None
    agent_summary: dict[str, Any] | None = None


class RunEnvelope(BaseModel):
    run: RunView


class RunListEnvelope(BaseModel):
    runs: list[RunView]
    limit: int
    offset: int


class LeaseInfo(BaseModel):
    heartbeat_interval_s: float
    heartbeat_timeout_s: float
    finish_grace_s: float


class Limits(BaseModel):
    max_batch_items: int
    max_body_bytes: int


class ClaimResponse(BaseModel):
    run: RunView
    lease_token: str
    lease: LeaseInfo
    limits: Limits


class HeartbeatResponse(BaseModel):
    status: str
    cancel_requested: bool
    heartbeat_timeout_s: float


class RejectedItem(BaseModel):
    seq: int
    code: str


class ObservationsResponse(BaseModel):
    accepted: int
    duplicates: int
    rejected: list[RejectedItem]
    conflicts: list[int]
    status: str
    cancel_requested: bool


# ------------------------------------------------------------------ mapping from the domain's dictionaries
def run_view(run: dict, *, with_summary: bool = True) -> dict:
    """The public form of a run (see service.api_view, which also builds the views embedded in errors)."""
    return service.api_view(run, with_summary=with_summary)
