"""API errors: one exception type, one JSON envelope, a fixed vocabulary of codes.

Every non-2xx response has the shape

    {"error": {"code": "<fixed identifier>", "message": "<fixed sentence>", "details": {...}}}

Messages are fixed sentences and `details` carries only run state (status, stop reason, ...) or the names of fields the
caller got wrong. Nothing here ever contains request content, lease tokens or hashes, SQL, file paths or a traceback.
"""
from __future__ import annotations

import sqlite3
from typing import Any


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict | None = None, headers: dict | None = None):
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}
        self.headers = headers or {}

    def body(self) -> dict:
        return {"error": {"code": self.code, "message": self.message, "details": self.details}}


def state_details(run: dict) -> dict:
    """What a caller may learn about a run it cannot act on: its state, never its internals."""
    return {"status": run["status"], "stop_reason": run["stop_reason"], "cancel_requested": run["cancel_requested"]}


# ---- 400 / 413 / 422
def malformed_json() -> ApiError:
    return ApiError(400, "malformed_json", "The request body is not valid JSON.")


def payload_too_large(limit: int) -> ApiError:
    return ApiError(413, "payload_too_large", "The request body is too large.", {"max_bytes": limit})


def validation_failed(problems: list[dict]) -> ApiError:
    return ApiError(422, "validation_failed", "The request is not valid.", {"problems": problems})


def invalid_config(details: dict | None = None) -> ApiError:
    return ApiError(422, "invalid_config", "The run configuration is not acceptable.", details)


def batch_too_large(limit: int) -> ApiError:
    return ApiError(422, "batch_too_large", "The batch has too many items.", {"max_items": limit})


def bad_batch_item() -> ApiError:
    return ApiError(422, "bad_batch_item", "Every batch item must be a [seq, record] pair with a non-negative integer seq.")


def unknown_schedule() -> ApiError:
    return ApiError(422, "unknown_schedule", "A scheduled run needs an existing schedule_id; a manual run must not have one.")


# ---- 403 / 404
def invalid_lease() -> ApiError:
    return ApiError(403, "invalid_lease", "The run token is missing or does not belong to this run.")


def host_not_allowed() -> ApiError:
    return ApiError(403, "host_not_allowed", "This service answers only on its local addresses.")


def origin_not_allowed() -> ApiError:
    return ApiError(403, "origin_not_allowed", "Requests from this origin are not accepted.")


def run_not_found() -> ApiError:
    return ApiError(404, "run_not_found", "No such run.")


def certificate_not_found() -> ApiError:
    return ApiError(404, "certificate_not_found", "No such certificate.")


# ---- 409
def run_not_claimable(run: dict) -> ApiError:
    return ApiError(409, "run_not_claimable", "Only a queued run can be claimed.", state_details(run))


def unsupported_run_type(run_type: str) -> ApiError:
    return ApiError(409, "unsupported_run_type", "This backend cannot hand out runs of this type yet.", {"type": run_type})


def run_not_running(run: dict) -> ApiError:
    return ApiError(409, "run_not_running", "The run is not running.", state_details(run))


def lease_overdue(run: dict) -> ApiError:
    return ApiError(409, "lease_overdue", "The run missed its heartbeat deadline; only finish is still accepted.",
                    state_details(run))


def run_already_finished(run: dict) -> ApiError:
    """Carries the final view: a client whose finish response was lost treats this as 'the run is over, here is how'."""
    return ApiError(409, "run_already_finished", "The run has already finished.", {**state_details(run), "run": run})


def run_not_cancellable(run: dict) -> ApiError:
    return ApiError(409, "run_not_cancellable", "The run has already finished and was not cancelled.", state_details(run))


def wrong_run_type(required: str) -> ApiError:
    return ApiError(409, "wrong_run_type", "This report is not available for this type of run.", {"required_type": required})


# ---- 5xx
def query_timeout(budget_seconds: float) -> ApiError:
    return ApiError(503, "query_timeout", "The request took too long and was stopped. Narrow the filters and try again.",
                    {"budget_seconds": budget_seconds}, headers={"Retry-After": "1"})


def busy() -> ApiError:
    return ApiError(503, "busy", "The service is busy; retry shortly.", headers={"Retry-After": "1"})


def internal_error() -> ApiError:
    return ApiError(500, "internal_error", "Something went wrong on the server.")


def from_database_error(exc: Exception) -> ApiError:
    """The generic answer to a SQLite failure: busy when the database is locked, otherwise internal. No internals."""
    locked = isinstance(exc, sqlite3.OperationalError) and any(w in str(exc).lower() for w in ("locked", "busy"))
    return busy() if locked else internal_error()


def http_error(status: int) -> ApiError:
    names = {404: ("not_found", "No such resource."), 405: ("method_not_allowed", "Method not allowed.")}
    code, message = names.get(status, ("http_error", "The request could not be served."))
    return ApiError(status, code, message)


def problem(field: str, kind: str) -> dict[str, Any]:
    return {"field": field, "problem": kind}
