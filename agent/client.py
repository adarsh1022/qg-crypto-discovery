"""A small HTTP client for the local backend (standard library only).

It talks to the backend's run API: list queued runs, claim, heartbeat, upload observation batches, finish.

Safety rules kept here:
  * only loopback servers (127.0.0.1 / localhost) are accepted: the agent never sends results anywhere else;
  * the lease token lives in memory only; it is validated before use, sent only as the X-Run-Token header, and never
    appears in an exception message or a log line;
  * errors carry the server's fixed error code and a status number, never a response body, a request body or a path.
"""
from __future__ import annotations

import http.client
import json
import re
from typing import Callable
from urllib.parse import urlsplit

TOKEN_HEADER = "X-Run-Token"
RUN_TYPES = ("filesystem", "tls")           # what this agent can execute
LOOPBACK_HOSTS = ("127.0.0.1", "localhost")
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_RUN_ID = re.compile(r"[0-9a-f]{32}")
_TOKEN = re.compile(r"[0-9a-f]{32}")
_CODE = re.compile(r"[a-z0-9_]{1,64}")

Transport = Callable[[str, str, dict, "bytes | None"], "tuple[int, bytes]"]


class Unreachable(Exception):
    """The backend could not be reached or did not answer properly (connection refused, timeout, reset, ...)."""

    def __init__(self, kind: str):
        super().__init__(f"backend unreachable ({kind})")
        self.kind = kind


class BackendError(Exception):
    """The backend answered with an error. `code` is its fixed error identifier ('unknown_error' if it sent none)."""

    def __init__(self, status: int, code: str, details: dict | None = None):
        super().__init__(f"backend answered {status} {code}")
        self.status, self.code, self.details = status, code, details or {}


def parse_server_url(url: str) -> tuple[str, int]:
    """-> (host, port) of a plain http loopback URL such as http://127.0.0.1:8765. Anything else is refused."""
    if not isinstance(url, str):
        raise ValueError("the server URL must be text")
    parts = urlsplit(url.strip())
    if parts.scheme != "http":
        raise ValueError("the server URL must start with http:// (the backend is local and plain)")
    if parts.hostname not in LOOPBACK_HOSTS:
        raise ValueError("the agent only talks to a loopback server (127.0.0.1 or localhost)")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("the server URL must be just http://host:port")
    try:
        port = parts.port or 80
    except ValueError:
        raise ValueError("the server URL has an invalid port") from None
    return parts.hostname, port


class BackendClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8765", *, timeout: float = 30.0, transport: Transport | None = None):
        self._host, self._port = parse_server_url(base_url)
        self._timeout = timeout
        self._send = transport or self._http_send

    # ------------------------------------------------------------------ transport
    def _http_send(self, method: str, path: str, headers: dict, body: "bytes | None") -> "tuple[int, bytes]":
        connection = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)     # one per call: thread-safe
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise http.client.HTTPException("response too large")
            return response.status, data
        finally:
            connection.close()

    def _call(self, method: str, path: str, *, body: dict | None = None, token: str | None = None) -> dict:
        headers = {"Accept": "application/json"}
        payload = None
        if body is not None:
            payload = json.dumps(body, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
            headers["Content-Type"] = "application/json"
        if token is not None:
            if not _TOKEN.fullmatch(token):
                raise ValueError("malformed lease token")
            headers[TOKEN_HEADER] = token
        try:
            status, data = self._send(method, path, headers, payload)
        except (OSError, http.client.HTTPException) as exc:
            raise Unreachable(type(exc).__name__) from None
        try:
            parsed = json.loads(data) if data else None
        except ValueError:
            parsed = None
        if 200 <= status < 300:
            if not isinstance(parsed, dict):
                raise BackendError(status, "invalid_response")
            return parsed
        error = parsed.get("error") if isinstance(parsed, dict) else None
        code = error.get("code") if isinstance(error, dict) else None
        details = error.get("details") if isinstance(error, dict) and isinstance(error.get("details"), dict) else {}
        raise BackendError(status, code if isinstance(code, str) and _CODE.fullmatch(code) else "unknown_error", details)

    @staticmethod
    def _run_path(run_id: str, tail: str = "") -> str:
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise ValueError("malformed run id")
        return f"/api/runs/{run_id}{tail}"

    # ------------------------------------------------------------------ the run API
    def queued_filesystem_runs(self, limit: int = 100) -> list[dict]:
        found = self._call("GET", f"/api/runs?type=filesystem&status=queued&limit={int(limit)}")
        runs = found.get("runs")
        if not isinstance(runs, list):
            raise BackendError(200, "invalid_response")
        return [r for r in runs if isinstance(r, dict) and isinstance(r.get("run_id"), str)]

    def queued_runs(self, limit: int = 100) -> list[dict]:
        """Queued runs of every type this agent can execute (filesystem and tls), in one request."""
        found = self._call("GET", f"/api/runs?status=queued&limit={int(limit)}")
        runs = found.get("runs")
        if not isinstance(runs, list):
            raise BackendError(200, "invalid_response")
        return [r for r in runs if isinstance(r, dict) and isinstance(r.get("run_id"), str) and r.get("type") in RUN_TYPES]

    def claim(self, run_id: str, *, agent_id: str, hostname: str, os_name: str | None, agent_version: str | None) -> dict:
        body = {"agent_id": agent_id, "hostname": hostname, "os": os_name, "agent_version": agent_version}
        return self._call("POST", self._run_path(run_id, "/claim"), body=body)

    def heartbeat(self, run_id: str, token: str) -> dict:
        return self._call("POST", self._run_path(run_id, "/heartbeat"), token=token)

    def upload(self, run_id: str, token: str, items: list) -> dict:
        return self._call("POST", self._run_path(run_id, "/observations"), body={"items": items}, token=token)

    def finish(self, run_id: str, token: str, *, outcome: str, summary: dict | None = None, fatal_code: str | None = None) -> dict:
        return self._call("POST", self._run_path(run_id, "/finish"), token=token,
                          body={"outcome": outcome, "summary": summary, "fatal_code": fatal_code})
