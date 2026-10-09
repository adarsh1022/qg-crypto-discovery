"""HTTP API: run creation, reads, validation, the error envelope, size limit, and the local-only guards."""
import asyncio
import dataclasses
import json
import re

import pytest
from fastapi.testclient import TestClient

from agent.scan_config import ScanConfig
from apifx import BASE_URL, START, make_api
from backend import service
from backend.settings import Settings

HEX32 = re.compile(r"[0-9a-f]{32}")


def error_of(response):
    body = response.json()
    assert set(body) == {"error"} and set(body["error"]) == {"code", "message", "details"}, body
    return body["error"]


# =========================================================================== create
def test_create_a_filesystem_run(api):
    response = api.client.post("/api/runs", json={"type": "filesystem", "config": {"roots": ["C:\\certs"], "max_depth": 3}})
    assert response.status_code == 201
    run = response.json()["run"]
    assert HEX32.fullmatch(run["run_id"]) and run["run_number"] == 1
    assert (run["type"], run["trigger"], run["status"]) == ("filesystem", "manual", "queued")
    assert run["config"] == {"roots": ["C:\\certs"], "max_depth": 3}
    assert run["queued_at"] == "2026-03-01T12:00:00.000Z" and run["started_at"] is None and run["finished_at"] is None
    assert run["host_id"] is None and run["schedule_id"] is None and run["cancel_requested"] is False
    assert (run["record_count"], run["finding_count"], run["rejected_count"], run["error_count"]) == (0, 0, 0, 0)
    assert run["agent_summary"] is None and run["error_summary"] is None and run["stop_reason"] is None


def test_the_backend_generates_run_ids_and_numbers(api):
    runs = [api.create() for _ in range(3)]
    assert len({r["run_id"] for r in runs}) == 3 and [r["run_number"] for r in runs] == [1, 2, 3]


def test_a_client_cannot_choose_the_run_id_or_status(api):
    for extra in ({"run_id": "mine-1234"}, {"status": "running"}, {"run_number": 99}, {"lease_hash": "a" * 64}):
        response = api.client.post("/api/runs", json={"type": "filesystem", **extra})
        assert response.status_code == 422 and error_of(response)["code"] == "validation_failed"
        assert next(iter(extra)) not in response.text                              # hostile key names are not echoed back
    assert api.client.get("/api/runs").json()["runs"] == []


def test_a_tls_run_can_be_queued(api):
    run = api.create("tls", config={"duration_seconds": 30})
    assert run["type"] == "tls" and run["status"] == "queued" and run["config"] == {"duration_seconds": 30}


def test_scheduled_runs_need_an_existing_schedule(api):
    for body in ({"trigger": "scheduled"}, {"trigger": "scheduled", "schedule_id": "nope"}, {"schedule_id": "s1"}):
        response = api.client.post("/api/runs", json={"type": "filesystem", **body})
        assert response.status_code == 422 and error_of(response)["code"] == "unknown_schedule", body
    with api.connect() as conn:
        conn.execute("INSERT INTO schedules (schedule_id, run_type, interval_seconds, created_at) VALUES ('s1', 'filesystem', 3600, 'x')")
    run = api.create(trigger="scheduled", schedule_id="s1")
    assert run["trigger"] == "scheduled" and run["schedule_id"] == "s1"
    assert api.client.get("/api/runs").json()["runs"][0]["trigger"] == "scheduled"


def test_the_whole_request_is_persisted_immutably(api):
    run = api.create(config={"roots": ["C:\\a"], "extensions": [".pem"], "time_budget_seconds": 12.5})
    assert api.get(run["run_id"])["config"] == {"roots": ["C:\\a"], "extensions": [".pem"], "time_budget_seconds": 12.5}
    with api.connect() as conn:
        import sqlite3
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute("UPDATE runs SET config_json = '{}' WHERE run_id = ?", (run["run_id"],))


@pytest.mark.parametrize("config", [
    {"unknown": 1}, {"roots": "C:\\a"}, {"roots": [1]}, {"roots": [""]}, {"roots": ["a"] * 201}, {"extensions": {"a": 1}},
    {"max_file_bytes": 0}, {"max_file_bytes": -5}, {"max_file_bytes": "5"}, {"max_file_bytes": True}, {"max_file_bytes": 1.5},
    {"max_depth": -1}, {"max_depth": 1.5}, {"expiring_days": -1}, {"expiring_days": None},
    {"time_budget_seconds": 0}, {"time_budget_seconds": "10"}, {"time_budget_seconds": True}, {"max_entries": 10**13},
    {"exclude_paths": [None]},
])
def test_filesystem_config_shape_is_validated(api, config):
    response = api.client.post("/api/runs", json={"type": "filesystem", "config": config})
    assert response.status_code == 422 and error_of(response)["code"] == "invalid_config", config
    assert api.client.get("/api/runs").json()["runs"] == []


def test_unknown_config_keys_are_not_echoed(api):
    response = api.client.post("/api/runs", json={"type": "filesystem", "config": {"super_secret_name": 1}})
    assert "super_secret_name" not in response.text and "allowed_keys" in error_of(response)["details"]


def test_the_agents_scan_config_fields_are_exactly_the_accepted_keys():
    assert service.FS_CONFIG_KEYS == {f.name for f in dataclasses.fields(ScanConfig)}


@pytest.mark.parametrize("config", [{"private_key": "x"}, {"nested": {"password": "p"}}, {"pem": "x"},
                                    {"note": "-----BEGIN CERTIFICATE-----"}, {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}])
def test_raw_material_cannot_be_smuggled_into_a_run_config(api, config):
    response = api.client.post("/api/runs", json={"type": "tls", "config": config})
    assert response.status_code == 422 and error_of(response)["code"] == "invalid_config"
    assert "BEGIN" not in response.text and api.client.get("/api/runs").json()["runs"] == []


@pytest.mark.parametrize("body", [{}, {"type": "dns"}, {"type": 5}, {"type": "filesystem", "trigger": "api"},
                                  {"type": "filesystem", "config": []}, {"type": "filesystem", "config": "x"},
                                  {"type": "filesystem", "schedule_id": "bad id!"}, {"type": "filesystem", "extra": 1}])
def test_malformed_create_requests_are_validation_errors(api, body):
    response = api.client.post("/api/runs", json=body)
    assert response.status_code == 422 and error_of(response)["code"] in ("validation_failed", "unknown_schedule")


def test_create_never_exposes_a_lease(api):
    run = api.create()
    assert "lease" not in json.dumps(run).lower() and "token" not in json.dumps(run).lower()


# =========================================================================== reads
def test_get_one_run_and_unknown_run(api):
    run = api.create()
    assert api.get(run["run_id"]) == run
    response = api.client.get("/api/runs/does-not-exist")
    assert response.status_code == 404 and error_of(response)["code"] == "run_not_found"


def test_list_filters_pages_and_orders_newest_first(api):
    ids = [api.create("filesystem" if i % 2 == 0 else "tls")["run_id"] for i in range(5)]
    api.cancel(ids[0])
    listing = api.client.get("/api/runs").json()
    assert [r["run_number"] for r in listing["runs"]] == [5, 4, 3, 2, 1] and listing["limit"] == 100 and listing["offset"] == 0
    assert all(r["agent_summary"] is None for r in listing["runs"])
    assert [r["run_number"] for r in api.client.get("/api/runs", params={"type": "tls"}).json()["runs"]] == [4, 2]
    assert [r["run_number"] for r in api.client.get("/api/runs", params={"status": "failed"}).json()["runs"]] == [1]
    assert [r["run_number"] for r in api.client.get("/api/runs", params={"limit": 2, "offset": 1}).json()["runs"]] == [4, 3]
    assert api.client.get("/api/runs", params={"limit": 0}).json()["runs"] == []


@pytest.mark.parametrize("params", [{"type": "dns"}, {"status": "paused"}, {"limit": -1}, {"limit": 1001}, {"offset": -1}, {"limit": "x"}])
def test_list_query_parameters_are_validated(api, params):
    response = api.client.get("/api/runs", params=params)
    assert response.status_code == 422 and error_of(response)["code"] == "validation_failed"


# =========================================================================== error envelope
def test_unknown_routes_and_methods_use_the_envelope(api):
    missing = api.client.get("/api/nothing")
    assert missing.status_code == 404 and error_of(missing)["code"] == "not_found"
    wrong = api.client.delete("/api/runs")
    assert wrong.status_code == 405 and error_of(wrong)["code"] == "method_not_allowed"
    assert api.client.get("/docs").status_code == 404 and api.client.get("/openapi.json").status_code == 404


def test_malformed_json_is_a_400(api):
    response = api.client.post("/api/runs", content=b'{"type": ', headers={"content-type": "application/json"})
    assert response.status_code == 400 and error_of(response)["code"] == "malformed_json"


@pytest.mark.parametrize("content, content_type", [(b"type=filesystem", "application/x-www-form-urlencoded"),
                                                   (b"", "application/json"), (b"[]", "application/json"),
                                                   (b"null", "application/json"), (b'"text"', "application/json")])
def test_wrong_bodies_are_validation_or_json_errors(api, content, content_type):
    response = api.client.post("/api/runs", content=content, headers={"content-type": content_type})
    assert response.status_code in (400, 422) and error_of(response)["code"] in ("malformed_json", "validation_failed")


def test_validation_errors_report_fields_and_kinds_but_never_values(api):
    secret = "SUPER-SECRET-VALUE-123"
    response = api.client.post("/api/runs", json={"type": secret, "trigger": secret, "config": {"roots": secret}})
    assert secret not in response.text and "input" not in response.text
    problems = error_of(response)["details"]["problems"]
    assert {p["field"] for p in problems} >= {"type", "trigger"} and all(set(p) == {"field", "problem"} for p in problems)


def test_error_bodies_never_contain_internals(api):
    run = api.create()
    for response in (api.client.get("/api/runs/nope"), api.cancel("nope"), api.client.post("/api/runs", json={}),
                     api.client.post(f"/api/runs/{run['run_id']}/heartbeat")):
        text = response.text.lower()
        assert not any(w in text for w in ("traceback", "sqlite", "select ", "lease_hash", "c:\\users", ".py"))


# =========================================================================== size limit
def test_an_oversized_declared_body_is_refused(tmp_path):
    api = make_api(tmp_path, max_body_bytes=2000)
    response = api.client.post("/api/runs", json={"type": "tls", "config": {"note": "x" * 5000}})
    assert response.status_code == 413 and error_of(response)["code"] == "payload_too_large"
    assert error_of(response)["details"] == {"max_bytes": 2000} and api.client.get("/api/runs").json()["runs"] == []
    assert api.client.post("/api/runs", json={"type": "tls", "config": {"note": "x" * 100}}).status_code == 201


def asgi_post(app, path, chunks, headers=()):
    """Drive the ASGI app directly so the body can be streamed without a Content-Length."""
    sent = []
    queue = list(chunks)

    async def receive():
        if queue:
            body = queue.pop(0)
            return {"type": "http.request", "body": body, "more_body": bool(queue)}
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "path": path, "raw_path": path.encode(),
             "query_string": b"", "headers": [(b"host", b"127.0.0.1"), (b"content-type", b"application/json"), *headers],
             "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 80), "scheme": "http"}
    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"], json.loads(b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"))


def test_a_streamed_body_over_the_limit_is_refused_without_content_length(tmp_path):
    api = make_api(tmp_path, max_body_bytes=2000)
    payload = json.dumps({"type": "tls", "config": {"note": "y" * 5000}}).encode()
    status, body = asgi_post(api.app, "/api/runs", [payload[:1500], payload[1500:3000], payload[3000:]])
    assert status == 413 and body["error"]["code"] == "payload_too_large"
    small = json.dumps({"type": "tls"}).encode()
    status, body = asgi_post(api.app, "/api/runs", [small[:5], small[5:]])
    assert status == 201 and body["run"]["status"] == "queued"
    assert len(api.client.get("/api/runs").json()["runs"]) == 1


def test_a_declared_oversize_body_is_refused_without_reading_it(tmp_path):
    api = make_api(tmp_path, max_body_bytes=2000)
    reads = []
    sent = []

    async def receive():
        reads.append(1)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "path": "/api/runs", "raw_path": b"/api/runs",
             "query_string": b"", "headers": [(b"host", b"127.0.0.1"), (b"content-type", b"application/json"), (b"content-length", b"999999")],
             "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 80), "scheme": "http"}
    asyncio.run(api.app(scope, receive, send))
    assert reads == [] and sent[0]["status"] == 413


def test_request_models_are_strict_and_forbid_extra_fields():
    from backend import api_models
    for model in (api_models.CreateRunRequest, api_models.ClaimRequest, api_models.ObservationsRequest, api_models.FinishRequest):
        assert model.model_config["strict"] is True and model.model_config["extra"] == "forbid", model.__name__


# =========================================================================== local-only guards
@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.1:8000", "localhost", "LOCALHOST:5173", "[::1]", "[::1]:8000"])
def test_loopback_hosts_are_served(tmp_path, host):
    api = make_api(tmp_path)
    assert api.client.get("/api/runs", headers={"host": host}).status_code == 200


@pytest.mark.parametrize("host", ["evil.example", "evil.example:80", "127.0.0.1.evil.example", "10.0.0.5", "0.0.0.0", ""])
def test_foreign_hosts_are_refused(api, host):
    response = api.client.get("/api/runs", headers={"host": host})
    assert response.status_code == 403 and error_of(response)["code"] == "host_not_allowed"


@pytest.mark.parametrize("origin", ["http://evil.example", "https://evil.example:443", "null", "http://127.0.0.1.evil.example",
                                    "file://", "ftp://localhost"])
def test_foreign_browser_origins_are_refused(api, origin):
    response = api.client.post("/api/runs", json={"type": "tls"}, headers={"origin": origin})
    assert response.status_code == 403 and error_of(response)["code"] == "origin_not_allowed"
    assert api.client.get("/api/runs").json()["runs"] == []


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:8000", "https://localhost", "http://[::1]:3000"])
def test_loopback_origins_are_accepted(api, origin):
    assert api.client.post("/api/runs", json={"type": "tls"}, headers={"origin": origin}).status_code == 201


def test_extra_origins_come_from_settings_only(tmp_path):
    api = make_api(tmp_path, allowed_origins=("https://ui.example.test/",))
    assert api.client.get("/api/runs", headers={"origin": "https://ui.example.test"}).status_code == 200
    assert api.client.get("/api/runs", headers={"origin": "https://other.example.test"}).status_code == 403


def test_agents_send_no_origin_and_are_not_affected(api):
    assert api.client.post("/api/runs", json={"type": "tls"}).status_code == 201


# =========================================================================== settings
@pytest.mark.parametrize("kwargs", [dict(db_path=":memory:"), dict(heartbeat_interval_s=0), dict(heartbeat_interval_s=90),
                                    dict(heartbeat_interval_s=float("nan")), dict(max_batch_items=0), dict(max_body_bytes=True),
                                    dict(sweep_interval_s=0), dict(sweep_interval_s=True), dict(allowed_hosts=()), dict(allowed_hosts=("",))])
def test_invalid_settings_are_refused(tmp_path, kwargs):
    kwargs.setdefault("db_path", tmp_path / "x.db")
    with pytest.raises(ValueError):
        Settings(**kwargs)


def test_the_database_is_created_and_migrated_when_the_app_is_built(tmp_path):
    api = make_api(tmp_path)
    assert api.db_path.exists()
    with api.connect() as conn:
        from backend import db
        assert db.schema_version(conn) == db.latest_version() and db.data_origin(conn) == "agent"


def test_a_sample_database_cannot_be_served_as_agent_data(tmp_path):
    from backend import db
    db.open_database(tmp_path / "sample.db", "sample").close()
    with pytest.raises(db.OriginMismatch):
        make_api(tmp_path, name="sample.db")
