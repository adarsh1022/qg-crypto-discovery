"""Read-only relationship endpoint: a thin route over backend/relationships.py.

Built like report_routes / tls_report_routes (same route class, `no-store`, strict query parsing, one read-only snapshot and one
time budget per request, one error envelope). It serves BOTH run types: the relationships of a filesystem run are its
`stored_on` edges, those of a TLS run its `presented_certificate` edges.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from . import relationship_models as models
from .relationships import get_relationships
from .report_routes import ReportRoute, no_store, parse_query, serve

RELATIONSHIP_PARAMS = {"limit": "int"}

router = APIRouter(prefix="/api", dependencies=[Depends(no_store)], route_class=ReportRoute)


@router.get("/runs/{run_id}/relationships", response_model=models.RelationshipPage)
def run_relationships(run_id: str, request: Request):
    return serve(request, lambda conn, budget, values: get_relationships(conn, run_id, budget=budget, **values),
                 prepare=lambda: parse_query(request, RELATIONSHIP_PARAMS))
