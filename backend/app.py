"""The FastAPI application: thin routes over backend/service.py.

A route does exactly this: take the request's arrival time and one database connection, call a service function, and
shape the result. No business rule lives here. Errors leave through one set of handlers that produce the envelope
described in errors.py; none of them ever includes a request body, a token, SQL or a traceback.

Local-only hygiene (not authentication): requests must name a loopback Host, and a browser Origin, if present, must be
a loopback origin or one listed in settings.allowed_origins. Bodies larger than settings.max_body_bytes are refused.
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import logging
import sqlite3
import time
from typing import Callable, Iterator, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, FastAPI, Header, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import api_models as models
from . import db, errors, fs_ingest, report_routes, run_state as rs, runs, service, tls_report_routes
from .errors import ApiError
from .safety import sanitize_text
from .settings import Settings

log = logging.getLogger("backend.api")
MAX_PROBLEMS = 20


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ------------------------------------------------------------------ ASGI guards
async def _send_json(send, status: int, payload: dict, headers: dict | None = None) -> None:
    body = json.dumps(payload).encode("utf-8")
    raw = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    raw += [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    await send({"type": "http.response.start", "status": status, "headers": raw})
    await send({"type": "http.response.body", "body": body})


def _host_name(header: str) -> str:
    host = header.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        return host[:end + 1] if end != -1 else host
    return host.rsplit(":", 1)[0] if ":" in host else host


class LocalOnlyMiddleware:
    """Reject requests whose Host is not a local address (DNS rebinding) or whose browser Origin is foreign (CSRF)."""

    def __init__(self, app, allowed_hosts: tuple[str, ...], allowed_origins: tuple[str, ...]):
        self.app, self.hosts, self.origins = app, frozenset(allowed_hosts), frozenset(allowed_origins)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k: v for k, v in scope["headers"]}
        if _host_name(headers.get(b"host", b"").decode("latin-1")) not in self.hosts:
            return await _send_json(send, 403, errors.host_not_allowed().body())
        origin = headers.get(b"origin")
        if origin is not None and not self._origin_ok(origin.decode("latin-1")):
            return await _send_json(send, 403, errors.origin_not_allowed().body())
        return await self.app(scope, receive, send)

    def _origin_ok(self, origin: str) -> bool:
        origin = origin.strip().lower().rstrip("/")
        if origin in self.origins:
            return True
        parts = urlsplit(origin)
        host = parts.hostname or ""
        host = f"[{host}]" if ":" in host else host
        return parts.scheme in ("http", "https") and host in self.hosts


class BodyTooLarge(StarletteHTTPException):
    """Raised while a body is being read. It is an HTTPException on purpose: FastAPI lets those through untouched, whereas
    any other exception raised during body parsing is turned into a generic 400."""

    def __init__(self, limit: int):
        super().__init__(status_code=413, detail="payload too large")
        self.limit = limit


class BodyLimitMiddleware:
    """Refuse bodies over the limit, whether declared (Content-Length) or discovered while reading (chunked)."""

    def __init__(self, app, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        declared = dict(scope["headers"]).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > self.max_bytes:
            return await _send_json(send, 413, errors.payload_too_large(self.max_bytes).body())
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise BodyTooLarge(self.max_bytes)
            return message
        await self.app(scope, limited_receive, send)


# ------------------------------------------------------------------ dependencies
def get_now(request: Request) -> dt.datetime:
    """The request's arrival time. Declared before the route body runs, so it is read before any wait for the write lock."""
    return request.app.state.clock()


def get_ctx(request: Request) -> service.Context:
    return request.app.state.ctx


class Database:
    """Opens a connection for ONE request, in the thread that uses it.

    A sqlite3 connection belongs to the thread that created it. FastAPI runs a (sync) dependency and the route body in
    different worker threads, so a connection created by a dependency would be used from the wrong thread as soon as
    requests overlap. The route therefore opens its connection itself, inside its own body, and the thread check stays on.
    """

    def __init__(self, path):
        self.path = path

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = db.connect(self.path)
        try:
            yield conn
        finally:
            conn.close()


def get_database(request: Request) -> Database:
    return Database(request.app.state.settings.db_path)


def run_token(x_run_token: str | None = Header(default=None)) -> str | None:
    return x_run_token


# ------------------------------------------------------------------ routes (thin)
router = APIRouter(prefix="/api/runs")


@router.post("", status_code=201, response_model=models.RunEnvelope)
def create_run(body: models.CreateRunRequest, now=Depends(get_now), ctx=Depends(get_ctx), database=Depends(get_database)):
    with database.connection() as conn:
        run = service.create_run(conn, ctx, now, run_type=body.type, trigger=body.trigger,
                                 schedule_id=body.schedule_id, config=body.config)
    return {"run": models.run_view(run)}


@router.get("", response_model=models.RunListEnvelope)
def list_runs(type: Literal["filesystem", "tls"] | None = None,
              status: Literal["queued", "running", "completed", "partial", "failed"] | None = None,
              limit: int = Query(100, ge=0, le=1000), offset: int = Query(0, ge=0), database=Depends(get_database)):
    with database.connection() as conn:
        found = service.list_runs(conn, run_type=type, status=status, limit=limit, offset=offset)
    return {"runs": [models.run_view(r, with_summary=False) for r in found], "limit": limit, "offset": offset}


@router.get("/{run_id}", response_model=models.RunEnvelope)
def get_run(run_id: str, database=Depends(get_database)):
    with database.connection() as conn:
        run = service.get_run(conn, run_id)
    return {"run": models.run_view(run)}


@router.post("/{run_id}/claim", response_model=models.ClaimResponse)
def claim_run(run_id: str, body: models.ClaimRequest, response: Response, now=Depends(get_now), ctx=Depends(get_ctx),
              database=Depends(get_database)):
    with database.connection() as conn:
        claim = service.claim_run(conn, ctx, now, run_id, agent_id=body.agent_id, hostname=body.hostname,
                                  os_name=body.os, agent_version=body.agent_version)
    response.headers["Cache-Control"] = "no-store"                  # the body carries the only copy of the lease token
    timeouts, settings = ctx.settings.timeouts, ctx.settings
    return {"run": models.run_view(claim.run), "lease_token": claim.lease_token,
            "lease": {"heartbeat_interval_s": settings.heartbeat_interval_s, "heartbeat_timeout_s": timeouts.heartbeat_s,
                      "finish_grace_s": timeouts.finish_grace_s},
            "limits": {"max_batch_items": settings.max_batch_items, "max_body_bytes": settings.max_body_bytes}}


@router.post("/{run_id}/heartbeat", response_model=models.HeartbeatResponse)
def heartbeat(run_id: str, token=Depends(run_token), now=Depends(get_now), ctx=Depends(get_ctx),
              database=Depends(get_database)):
    with database.connection() as conn:
        beat = service.heartbeat(conn, ctx, now, run_id, token)
    return {"status": beat.status, "cancel_requested": beat.cancel_requested,
            "heartbeat_timeout_s": ctx.settings.timeouts.heartbeat_s}


@router.post("/{run_id}/cancel", response_model=models.RunEnvelope)
def cancel_run(run_id: str, now=Depends(get_now), ctx=Depends(get_ctx), database=Depends(get_database)):
    with database.connection() as conn:
        run = service.cancel_run(conn, ctx, now, run_id)
    return {"run": models.run_view(run)}


@router.post("/{run_id}/observations", response_model=models.ObservationsResponse)
def upload_observations(run_id: str, body: models.ObservationsRequest, token=Depends(run_token), now=Depends(get_now),
                        ctx=Depends(get_ctx), database=Depends(get_database)):
    with database.connection() as conn:
        done = service.ingest_observations(conn, ctx, now, run_id, token, body.items)
    return {"accepted": done.batch.accepted, "duplicates": done.batch.duplicates,
            "rejected": [{"seq": seq, "code": code} for seq, code in done.batch.rejected],
            "conflicts": list(done.batch.conflicts), "status": done.status, "cancel_requested": done.cancel_requested}


@router.post("/{run_id}/finish", response_model=models.RunEnvelope)
def finish_run(run_id: str, body: models.FinishRequest, token=Depends(run_token), now=Depends(get_now),
               ctx=Depends(get_ctx), database=Depends(get_database)):
    with database.connection() as conn:
        run = service.finish_run(conn, ctx, now, run_id, token, outcome=body.outcome, summary=body.summary,
                                 fatal_code=body.fatal_code)
    return {"run": models.run_view(run)}


# ------------------------------------------------------------------ error handlers
def _json(error: ApiError) -> JSONResponse:
    return JSONResponse(status_code=error.status, content=error.body(), headers=error.headers or None)


def _problems(exc: RequestValidationError) -> list[dict]:
    """Which fields were wrong and why, never what was sent (not even hostile key names)."""
    out = []
    for err in exc.errors()[:MAX_PROBLEMS]:
        loc = [p for p in err["loc"] if p not in ("body", "query", "header", "path")]
        if err["type"] == "extra_forbidden" and loc:
            loc = loc[:-1]                                      # the offending key name is caller-chosen: do not echo it
        out.append(errors.problem(".".join(sanitize_text(str(p))[:40] for p in loc) or "body", str(err["type"])))
    return out


def _install_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def api_error(_: Request, exc: ApiError):
        return _json(exc)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_: Request, exc: RequestValidationError):
        if any(err["type"] == "json_invalid" for err in exc.errors()):
            return _json(errors.malformed_json())
        return _json(errors.validation_failed(_problems(exc)))

    @app.exception_handler(BodyTooLarge)
    async def body_too_large(_: Request, exc: BodyTooLarge):
        return _json(errors.payload_too_large(exc.limit))

    @app.exception_handler(StarletteHTTPException)
    async def http_exception(_: Request, exc: StarletteHTTPException):
        return _json(errors.http_error(exc.status_code))

    @app.exception_handler(runs.RunNotFound)
    async def run_not_found(_: Request, exc: runs.RunNotFound):
        return _json(errors.run_not_found())

    @app.exception_handler(rs.InvalidTransition)
    async def invalid_transition(_: Request, exc: rs.InvalidTransition):      # defensive: services check state first
        return _json(ApiError(409, "invalid_transition", "The run is not in a state that allows this."))

    @app.exception_handler(sqlite3.Error)
    async def database_error(_: Request, exc: sqlite3.Error):
        log.error("database error: %s", type(exc).__name__)                    # the class only: messages can quote data
        return _json(errors.from_database_error(exc))

    @app.exception_handler(Exception)
    async def unexpected(_: Request, exc: Exception):
        log.error("unhandled error: %s", type(exc).__name__)
        return _json(errors.internal_error())


# ------------------------------------------------------------------ recovery task
def sweep_once(app: FastAPI) -> int:
    conn = db.connect(app.state.settings.db_path)
    try:
        return service.sweep(conn, app.state.ctx, app.state.clock())
    finally:
        conn.close()


async def _sweep_loop(app: FastAPI, interval: float) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(sweep_once, app)
        except Exception as exc:                                              # noqa: BLE001 - keep sweeping
            log.error("sweep failed: %s", type(exc).__name__)


# ------------------------------------------------------------------ factory
def create_app(settings: Settings, *, clock: Callable[[], dt.datetime] = utc_now,
               budget_clock: Callable[[], float] = time.monotonic) -> FastAPI:
    db.open_database(settings.db_path, settings.data_origin).close()          # create / migrate once, up front

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(_sweep_loop(app, settings.sweep_interval_s)) if settings.sweep_interval_s else None
        try:
            yield
        finally:
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(title="QuantumGenie local backend", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.clock = clock
    app.state.budget_clock = budget_clock                 # the report time budget runs on its own (monotonic) clock
    app.state.ctx = service.Context(settings=settings, not_before=clock())
    _install_handlers(app)
    app.include_router(report_routes.router)            # first: /api/runs/stats must not be read as /api/runs/{run_id}
    app.include_router(tls_report_routes.router)
    app.include_router(router)
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(LocalOnlyMiddleware, allowed_hosts=settings.allowed_hosts, allowed_origins=settings.allowed_origins)
    return app
