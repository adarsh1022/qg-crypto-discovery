"""Read-only report endpoints: thin routes over backend/reports.py and backend/summaries.py.

A route does exactly this: parse the query strictly, open ONE read-only connection and one snapshot under one time
budget, call the report function, and let the response model drop everything that is not published. Nothing here
writes, expires runs or touches the lease protocol.

Query strings are validated before anything else: unknown or repeated parameters, empty values, anything but ASCII
digits for a number and anything but true/false for a flag are refused with 422 `validation_failed`. Error bodies name
fixed parameter names only, never a value and never an unknown parameter's name.

Failures leave through ApiError with `Cache-Control: no-store`, translated HERE (a wrong run type, a timeout, an invalid
query): the write paths and the application-wide handlers are untouched. Every report response, success or error, is
marked no-store because paths, subjects and SANs are sensitive local metadata.
"""
from __future__ import annotations

import logging
import re
import sqlite3
from collections import Counter
from typing import Any, Callable

from fastapi import APIRouter, Depends, Request, Response
from fastapi.exceptions import ResponseValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from . import db, errors, reports, run_state as rs, runs, summaries
from . import report_models as models
from .errors import ApiError, problem
from .reports import InvalidQuery, SightingQuery, UniqueQuery

log = logging.getLogger("backend.api")
_INTEGER = re.compile(r"[0-9]{1,19}")
_DIGITS = re.compile(r"[0-9]+")
HTTP_NAMES = {"top_n": "top"}                          # domain parameter name -> the name the caller used
HTTP_UNIQUE_SORTS = tuple(name for name in reports.UNIQUE_SORTS if name != "first_seq")      # first_seq is not a published field

SIGHTING_PARAMS = {
    "parse_status": "str", "validity_status": "str", "format": "str", "chain_role": "str", "evidence_confidence": "str",
    "key_algorithm": "str", "key_size": "int", "signature_algorithm": "str", "scan_root": "str", "issuer": "str",
    "has_warnings": "bool", "duplicate_kind": "str", "q": "str", "fingerprint": "str", "sort": "str", "direction": "str",
    "limit": "int", "offset": "int", "frontier": "int"}
UNIQUE_PARAMS = {
    "key_algorithm": "str", "key_size": "int", "signature_algorithm": "str", "issuer": "str", "q": "str", "fingerprint": "str",
    "sort": "str", "direction": "str", "limit": "int", "offset": "int", "frontier": "int"}
SUMMARY_PARAMS = {"top": "int", "frontier": "int"}
DASHBOARD_PARAMS = {"top": "int"}
STATS_PARAMS = {"type": "str", "since": "str", "limit": "int"}
ISSUE_PARAMS = {"limit": "int", "offset": "int"}
NO_PARAMS: dict[str, str] = {}


def no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


class ReportRoute(APIRoute):
    """FastAPI checks a response against its model AFTER the route function has returned, so serve() never sees a mismatch.
    Without this, a report that did not fit its model would bypass the report error handling: no `no-store`, and the
    exception (whose text quotes the offending values) would be re-raised to the server's log. Used by the report router
    only; every other route keeps the application-wide behavior."""

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def guarded(request: Request):
            try:
                return await handler(request)
            except ResponseValidationError as exc:
                log.error("report response failed validation: %s", type(exc).__name__)          # the class only: the text quotes the data
                error = errors.internal_error()
                return JSONResponse(status_code=error.status, content=error.body(), headers={"Cache-Control": "no-store"})
        return guarded


router = APIRouter(prefix="/api", dependencies=[Depends(no_store)], route_class=ReportRoute)


# ------------------------------------------------------------------ strict query parsing
def _nostore(error: ApiError) -> ApiError:
    error.headers = {**error.headers, "Cache-Control": "no-store"}
    return error


def parse_query(request: Request, spec: dict[str, str]) -> dict[str, Any]:
    """The query string as typed values, or ApiError 422 naming which parameters were wrong (never what was sent)."""
    problems: list[dict] = []

    def complain(field: str, kind: str) -> None:
        item = problem(field, kind)                               # at most one per parameter, so the list is bounded by the spec
        if item not in problems:
            problems.append(item)

    items = request.query_params.multi_items()
    counts = Counter(key for key, _ in items)
    values: dict[str, Any] = {}
    for key, raw in items:
        kind = spec.get(key)
        if kind is None:
            complain("query", "unknown_parameter")                 # the key is caller-chosen: not echoed
        elif counts[key] > 1:
            complain(key, "repeated_parameter")                    # refused even when every copy is valid
        elif raw == "":
            complain(key, "empty_value")
        elif kind == "int":
            if _INTEGER.fullmatch(raw):
                values[key] = int(raw)
            else:
                complain(key, "out_of_range" if _DIGITS.fullmatch(raw) else "not_an_integer")
        elif kind == "bool":
            if raw in ("true", "false"):
                values[key] = raw == "true"
            else:
                complain(key, "not_a_boolean")
        else:
            values[key] = raw
    if problems:
        raise errors.validation_failed(problems)                  # serve() adds the no-store header to every error
    return values


# ------------------------------------------------------------------ one read request
def serve(request: Request, work: Callable[[sqlite3.Connection, db.QueryBudget, Any], Any],
          prepare: Callable[[], Any] = lambda: None, required_type: str = "filesystem") -> Any:
    """Run `work` on a read-only connection inside one snapshot under one budget, translating failures.

    `required_type` is the run type the report is for; it only decides what a wrong-type 409 says (default: filesystem).
    `prepare` (validation that needs no database) runs first. The budget starts when the request arrives and covers the
    connection, the snapshot, every statement and the Python work in between. The connection is opened and closed in
    this thread, whatever happens.
    """
    state = request.app.state
    settings = state.settings
    budget = db.QueryBudget(settings.query_budget_s, clock=state.budget_clock)
    try:
        prepared = prepare()
        conn = db.connect(settings.db_path, read_only=True)
        try:
            with db.read_snapshot(conn, budget):
                return work(conn, budget, prepared)
        finally:
            conn.close()
    except ApiError as exc:
        raise _nostore(exc)
    except db.QueryTimeout:
        raise _nostore(errors.query_timeout(settings.query_budget_s)) from None
    except InvalidQuery as exc:
        raise _nostore(errors.validation_failed([problem(HTTP_NAMES.get(exc.field, exc.field), exc.problem)])) from None
    except runs.RunNotFound:
        raise _nostore(errors.run_not_found()) from None
    except runs.WrongRunType:
        raise _nostore(errors.wrong_run_type(required_type)) from None
    except sqlite3.Error as exc:
        log.error("database error: %s", type(exc).__name__)                    # the class only: messages can quote data
        raise _nostore(errors.from_database_error(exc)) from None
    except Exception as exc:                                                    # noqa: BLE001 - nothing leaks from a report
        log.error("unhandled error: %s", type(exc).__name__)
        raise _nostore(errors.internal_error()) from None


def _now(request: Request):
    return request.app.state.clock()


def _top(values: dict) -> dict:
    return {"top_n": values["top"]} if "top" in values else {}


def _page(page: reports.Page) -> dict:
    return {"items": page.items, "total": page.total, "limit": page.limit, "offset": page.offset, "frontier": page.frontier}


# ------------------------------------------------------------------ routes (order matters: /runs/stats before any /runs/{id})
@router.get("/meta", response_model=models.Meta)
def meta(request: Request):
    now = _now(request)
    return serve(request, lambda conn, budget, _: {"data_origin": db.data_origin(conn), "schema_version": db.schema_version(conn),
                                                   "server_time": rs.format_ts(now)},
                 prepare=lambda: parse_query(request, NO_PARAMS))


@router.get("/dashboard", response_model=models.Dashboard)
def dashboard(request: Request):
    now = _now(request)
    return serve(request, lambda conn, budget, values: summaries.dashboard(conn, now=now, budget=budget, **_top(values)),
                 prepare=lambda: parse_query(request, DASHBOARD_PARAMS))


@router.get("/runs/stats", response_model=models.RunStatistics)
def run_statistics(request: Request):
    def work(conn, budget, values):
        found = summaries.run_statistics(conn, run_type=values.get("type"), since=values.get("since"),
                                         **({"limit": values["limit"]} if "limit" in values else {}))
        return {"by_type_status": found["by_type_status"], "series": found["series"]}
    return serve(request, work, prepare=lambda: parse_query(request, STATS_PARAMS))


@router.get("/runs/{run_id}/fs/summary", response_model=models.Summary)
def fs_summary(run_id: str, request: Request):
    now = _now(request)
    return serve(request, lambda conn, budget, values: summaries.fs_summary(
        conn, run_id, now=now, frontier=values.get("frontier"), budget=budget, **_top(values)),
        prepare=lambda: parse_query(request, SUMMARY_PARAMS))


@router.get("/runs/{run_id}/fs/observations", response_model=models.SightingPage)
def fs_observations(run_id: str, request: Request):
    def prepare():
        return SightingQuery(**parse_query(request, SIGHTING_PARAMS))
    return serve(request, lambda conn, budget, query: _page(reports.search_sightings(conn, run_id, query)), prepare=prepare)


@router.get("/runs/{run_id}/fs/certificates", response_model=models.UniqueCertificatePage)
def fs_certificates(run_id: str, request: Request):
    def prepare():
        values = parse_query(request, UNIQUE_PARAMS)
        if values.get("sort") is not None and values["sort"] not in HTTP_UNIQUE_SORTS:
            raise errors.validation_failed([problem("sort", "unknown_value")])
        return UniqueQuery(**values)
    return serve(request, lambda conn, budget, query: _page(reports.search_unique_certificates(conn, run_id, query)), prepare=prepare)


@router.get("/runs/{run_id}/issues", response_model=models.IssuePage)
def run_issues(run_id: str, request: Request):
    return serve(request, lambda conn, budget, values: reports.list_issues(conn, run_id, **values),
                 prepare=lambda: parse_query(request, ISSUE_PARAMS))


@router.get("/certificates/{sha256}", response_model=models.CertificateDetail)
def certificate(sha256: str, request: Request):
    def work(conn, budget, _):
        found = reports.certificate_detail(conn, sha256)
        if found is None:
            raise errors.certificate_not_found()
        return found
    return serve(request, work, prepare=lambda: parse_query(request, NO_PARAMS))
