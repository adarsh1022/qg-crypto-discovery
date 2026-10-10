"""Helpers for agent-runner tests: the real agent client wired to a real FastAPI app in-process, with a call log and hooks."""
import json
import threading

from agent.client import BackendClient
from agent.runner import RunnerOptions

SERVER_URL = "http://127.0.0.1:8765"


class Wire:
    """An in-process transport to `api`. Records every call; `before`/`after` hooks can fail or alter a call."""

    def __init__(self, api, before=None, after=None):
        self.api, self.before, self.after = api, before, after
        self.calls = []                                   # (method, path-without-query, body_bytes, status or None)
        self._lock = threading.Lock()                     # one request at a time through the TestClient

    def __call__(self, method, path, headers, body):
        with self._lock:
            if self.before:
                self.before(self, method, path, body)
            response = self.api.client.request(method, path, content=body, headers=headers)
            self.calls.append((method, path.split("?")[0], body, response.status_code))
            if self.after:
                self.after(self, method, path, body, response)
            return response.status_code, response.content

    def paths(self, suffix):
        return [c for c in self.calls if c[1].endswith(suffix)]

    def uploads(self):
        """-> the decoded item lists of every observation upload that was sent."""
        return [json.loads(c[2])["items"] for c in self.paths("/observations")]


def make_client(api, **hooks):
    wire = Wire(api, **hooks)
    return BackendClient(SERVER_URL, transport=wire), wire


def options(**overrides):
    values = dict(agent_id="agent-test", hostname="TESTHOST", os_name="Windows test", batch_size=200, retry_delay=0.0)
    values.update(overrides)
    return RunnerOptions(**values)
