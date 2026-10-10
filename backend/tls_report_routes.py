"""Read-only TLS report endpoints: thin routes over backend/tls_reports.py.

Built exactly like report_routes (same route class, `no-store` on every response, strict query parsing, one read-only
snapshot and one time budget per request, one error envelope) and reusing its machinery. The filesystem report routes are
untouched: a tls run still answers them with 409 `wrong_run_type` (required type "filesystem"), and a filesystem run answers
these with 409 `wrong_run_type` (required type "tls").
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from . import tls_report_models as models
from . import report_models
from .report_routes import ISSUE_PARAMS, ReportRoute, _now, _page, _top, no_store, parse_query, serve
from .tls_reports import TlsObservationQuery, list_tls_issues, search_observations, tls_summary

TLS_OBSERVATION_PARAMS = {
    "outcome": "str", "tls_version": "str", "process_attribution": "str", "dst_port": "int", "fingerprint": "str", "q": "str",
    "sort": "str", "direction": "str", "limit": "int", "offset": "int", "frontier": "int"}
TLS_SUMMARY_PARAMS = {"top": "int", "frontier": "int"}

router = APIRouter(prefix="/api", dependencies=[Depends(no_store)], route_class=ReportRoute)


@router.get("/runs/{run_id}/tls/summary", response_model=models.TlsSummary)
def tls_run_summary(run_id: str, request: Request):
    now = _now(request)
    return serve(request, lambda conn, budget, values: tls_summary(
        conn, run_id, now=now, frontier=values.get("frontier"), budget=budget, **_top(values)),
        prepare=lambda: parse_query(request, TLS_SUMMARY_PARAMS), required_type="tls")


@router.get("/runs/{run_id}/tls/observations", response_model=models.TlsObservationPage)
def tls_run_observations(run_id: str, request: Request):
    def prepare():
        return TlsObservationQuery(**parse_query(request, TLS_OBSERVATION_PARAMS))
    return serve(request, lambda conn, budget, query: _page(search_observations(conn, run_id, query)), prepare=prepare,
                 required_type="tls")


@router.get("/runs/{run_id}/tls/issues", response_model=report_models.IssuePage)
def tls_run_issues(run_id: str, request: Request):
    return serve(request, lambda conn, budget, values: list_tls_issues(conn, run_id, **values),
                 prepare=lambda: parse_query(request, ISSUE_PARAMS), required_type="tls")
