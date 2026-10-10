"""Helpers for HTTP API tests: a controllable clock, an app on a temporary database, and a fake agent that speaks the protocol."""
import datetime as dt
import threading
from dataclasses import dataclass
from pathlib import Path

from fastapi.testclient import TestClient

from backend import db
from backend.app import create_app
from backend.run_state import Timeouts
from backend.settings import Settings

UTC = dt.timezone.utc
START = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
BASE_URL = "http://127.0.0.1"
TOKEN_HEADER = "X-Run-Token"


class FakeClock:
    """The backend's notion of 'now', moved by the test. Thread-safe so concurrent requests can read it."""

    def __init__(self, start: dt.datetime = START):
        self._now, self._lock = start, threading.Lock()

    def __call__(self) -> dt.datetime:
        with self._lock:
            return self._now

    def advance(self, seconds: float) -> dt.datetime:
        with self._lock:
            self._now += dt.timedelta(seconds=seconds)
            return self._now

    def set(self, moment: dt.datetime) -> None:
        with self._lock:
            self._now = moment


@dataclass
class Api:
    app: object
    client: TestClient
    clock: FakeClock
    settings: Settings
    db_path: Path

    def connect(self):
        return db.connect(self.db_path)

    def create(self, run_type="filesystem", **body):
        response = self.client.post("/api/runs", json={"type": run_type, **body})
        assert response.status_code == 201, response.text
        return response.json()["run"]

    def get(self, run_id):
        response = self.client.get(f"/api/runs/{run_id}")
        assert response.status_code == 200, response.text
        return response.json()["run"]

    def cancel(self, run_id):
        return self.client.post(f"/api/runs/{run_id}/cancel")

    def agent(self, **kwargs):
        return FakeAgent(self.client, **kwargs)


def make_api(tmp_path: Path, *, clock: FakeClock | None = None, name="api.db", budget_clock=None, **settings_kwargs) -> Api:
    clock = clock or FakeClock()
    settings_kwargs.setdefault("sweep_interval_s", None)             # tests drive expiry explicitly
    settings_kwargs.setdefault("schedule_tick_s", None)              # ... and the scheduler (schedules.tick) explicitly
    settings = Settings(db_path=tmp_path / name, **settings_kwargs)
    app = create_app(settings, clock=clock, **({"budget_clock": budget_clock} if budget_clock else {}))
    return Api(app=app, client=TestClient(app, base_url=BASE_URL), clock=clock, settings=settings, db_path=settings.db_path)


class FakeAgent:
    """What the real agent will do over HTTP: claim, heartbeat, upload numbered batches, finish."""

    def __init__(self, client: TestClient, agent_id="agent-1", hostname="WORKSTATION"):
        self.client, self.agent_id, self.hostname = client, agent_id, hostname
        self.run_id = self.token = None
        self.lease = self.limits = None

    def headers(self, token=None):
        return {TOKEN_HEADER: token if token is not None else self.token}

    def claim(self, run_id, **overrides):
        body = {"agent_id": self.agent_id, "hostname": self.hostname, "os": "Windows 11", "agent_version": "0.1"}
        body.update(overrides)
        response = self.client.post(f"/api/runs/{run_id}/claim", json=body)
        if response.status_code == 200:
            data = response.json()
            self.run_id, self.token, self.lease, self.limits = run_id, data["lease_token"], data["lease"], data["limits"]
        return response

    def heartbeat(self, run_id=None, token=None):
        return self.client.post(f"/api/runs/{run_id or self.run_id}/heartbeat", headers=self.headers(token))

    def upload(self, items, run_id=None, token=None):
        return self.client.post(f"/api/runs/{run_id or self.run_id}/observations", json={"items": items},
                                headers=self.headers(token))

    def upload_records(self, records, *, start=0, batch_size=100):
        responses = []
        for offset in range(0, len(records), batch_size):
            chunk = records[offset:offset + batch_size]
            responses.append(self.upload([[start + offset + i, r] for i, r in enumerate(chunk)]))
        return responses

    def finish(self, outcome="finished", summary=None, fatal_code=None, run_id=None, token=None):
        body = {"outcome": outcome, "summary": summary, "fatal_code": fatal_code}
        return self.client.post(f"/api/runs/{run_id or self.run_id}/finish", json=body, headers=self.headers(token))

    def scan_and_report(self, scan_root, **config):
        """Run the real Phase 1 scanner and report it through the API, the way the real agent will."""
        from treegen import run_scan
        records, summary = run_scan(scan_root, **config)
        uploads = self.upload_records(records)
        assert all(u.status_code == 200 for u in uploads), [u.text for u in uploads]
        return records, summary, self.finish(summary=summary)
