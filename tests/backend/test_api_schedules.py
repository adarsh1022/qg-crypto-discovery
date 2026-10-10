"""HTTP API for schedules: create, list, get, pause/resume, strict validation, the error envelope, the local-only guards, and the
whole path from a schedule to a scheduled run that the agent claims and finishes."""
import re

import pytest

from apifx import make_api
from backend.app import tick_once
from ingestfx import ok_record, summary

SCHEDULE_ID = re.compile(r"sched-[0-9a-f]{8}")
FS = {"run_type": "filesystem", "interval_seconds": 60, "config": {"roots": ["C:\\certs"]}}
TLS_PORTS = {"run_type": "tls", "interval_seconds": 30, "config": {"ports": [8443]}}
TLS_ALL = {"run_type": "tls", "interval_seconds": 30, "config": {}, "probe_all_listeners": True}


def error_of(response):
    body = response.json()
    assert set(body) == {"error"} and set(body["error"]) == {"code", "message", "details"}, body
    return body["error"]


def create(api, body=FS):
    response = api.client.post("/api/schedules", json=body)
    assert response.status_code == 201, response.text
    return response.json()["schedule"]


def runs_of(api):
    return api.client.get("/api/runs").json()["runs"]


# =========================================================================== create
def test_create_returns_201_and_the_documented_view(api):
    response = api.client.post("/api/schedules", json=FS)
    assert response.status_code == 201 and set(response.json()) == {"schedule"}
    view = response.json()["schedule"]
    assert SCHEDULE_ID.fullmatch(view["schedule_id"])
    assert view == {"schedule_id": view["schedule_id"], "run_type": "filesystem", "interval_seconds": 60,
                    "config": {"roots": ["C:\\certs"]}, "probe_all_listeners": False, "enabled": True, "state": "waiting",
                    "next_due_at": "2026-03-01T12:01:00.000Z", "created_at": "2026-03-01T12:00:00.000Z", "last_run": None, "run_count": 0}


def test_a_schedule_created_paused_has_no_next_due_time(api):
    view = create(api, {**FS, "enabled": False})
    assert (view["enabled"], view["state"], view["next_due_at"]) == (False, "paused", None)


def test_a_tls_schedule_with_ports_and_one_with_the_explicit_opt_in(api):
    ports = create(api, TLS_PORTS)
    broad = create(api, TLS_ALL)
    assert ports["probe_all_listeners"] is False and ports["config"] == {"ports": [8443]}
    assert broad["probe_all_listeners"] is True and broad["config"] == {}


def test_a_tls_schedule_without_ports_and_without_the_opt_in_is_refused_by_the_backend(api):
    for body in ({"run_type": "tls", "interval_seconds": 30}, {"run_type": "tls", "interval_seconds": 30, "config": {}},
                 {"run_type": "tls", "interval_seconds": 30, "config": {"max_targets": 5}, "probe_all_listeners": False}):
        response = api.client.post("/api/schedules", json=body)
        assert response.status_code == 422, body
        assert error_of(response) == {"code": "invalid_schedule", "message": "The schedule is not acceptable.",
                                      "details": {"field": "probe_all_listeners", "problem": "required_without_ports"}}
    assert api.client.get("/api/schedules").json() == {"schedules": []}


@pytest.mark.parametrize("body, problem", [
    ({"run_type": "tls", "interval_seconds": 30, "config": {"ports": [1]}, "probe_all_listeners": True}, "conflicts_with_ports"),
    ({**FS, "probe_all_listeners": True}, "tls_only"),
])
def test_the_opt_in_is_refused_where_it_does_not_apply(api, body, problem):
    response = api.client.post("/api/schedules", json=body)
    assert response.status_code == 422 and error_of(response)["details"] == {"field": "probe_all_listeners", "problem": problem}


@pytest.mark.parametrize("interval", [14, 0, -5, 604801])
def test_out_of_range_intervals_are_refused_with_the_limits(api, interval):
    response = api.client.post("/api/schedules", json={**FS, "interval_seconds": interval})
    assert response.status_code == 422
    assert error_of(response)["code"] == "invalid_schedule"
    assert error_of(response)["details"] == {"field": "interval_seconds", "problem": "out_of_range", "min": 15, "max": 604800}


@pytest.mark.parametrize("interval", [15, 604800])
def test_the_limits_themselves_are_accepted(api, interval):
    assert create(api, {**FS, "interval_seconds": interval})["interval_seconds"] == interval


@pytest.mark.parametrize("interval", [True, False, 30.5, 30.0, "30", None, [30], {"a": 1}])
def test_an_interval_that_is_not_a_whole_number_is_a_validation_error(api, interval):
    response = api.client.post("/api/schedules", json={**FS, "interval_seconds": interval})
    assert response.status_code == 422 and error_of(response)["code"] == "validation_failed"
    assert api.client.get("/api/schedules").json() == {"schedules": []}


@pytest.mark.parametrize("body", [
    {}, {"run_type": "filesystem"}, {"interval_seconds": 60}, {"run_type": "dns", "interval_seconds": 60}, {"run_type": 5, "interval_seconds": 60},
    {**FS, "config": []}, {**FS, "config": "x"}, {**FS, "enabled": "yes"}, {**FS, "enabled": 1}, {**FS, "probe_all_listeners": "true"},
    {**FS, "probe_all_listeners": 1},
])
def test_malformed_create_requests_are_validation_errors_and_create_nothing(api, body):
    response = api.client.post("/api/schedules", json=body)
    assert response.status_code == 422 and error_of(response)["code"] == "validation_failed"
    assert api.client.get("/api/schedules").json() == {"schedules": []}


def test_a_client_cannot_choose_the_id_the_due_time_or_the_last_run(api):
    for extra in ({"schedule_id": "mine"}, {"next_due_at": "2030-01-01T00:00:00.000Z"}, {"last_run_id": "x" * 32}, {"state": "paused"},
                  {"run_count": 99}, {"created_at": "x"}, {"trigger": "scheduled"}, {"lease_hash": "a" * 64}):
        response = api.client.post("/api/schedules", json={**FS, **extra})
        assert response.status_code == 422 and error_of(response)["code"] == "validation_failed", extra
        assert next(iter(extra)) not in response.text                          # hostile key names are not echoed back
    assert api.client.get("/api/schedules").json() == {"schedules": []}


@pytest.mark.parametrize("config", [{"unknown": 1}, {"roots": "C:\\a"}, {"max_depth": -1}, {"time_budget_seconds": True}])
def test_a_filesystem_configuration_is_validated_exactly_like_a_manual_runs(api, config):
    response = api.client.post("/api/schedules", json={**FS, "config": config})
    assert response.status_code == 422 and error_of(response)["code"] == "invalid_config"


def test_a_tls_configuration_cannot_name_a_target(api):
    for config in ({"hosts": ["8.8.8.8"]}, {"targets": ["10.0.0.1"]}, {"address": "1.1.1.1"}, {"ports": [0]}):
        response = api.client.post("/api/schedules", json={**TLS_PORTS, "config": config})
        assert response.status_code == 422 and error_of(response)["code"] == "invalid_config", config
        assert "8.8.8.8" not in response.text and "1.1.1.1" not in response.text and "10.0.0.1" not in response.text


@pytest.mark.parametrize("config", [{"roots": ["-----BEGIN CERTIFICATE-----"]}, {"private_key": "x"}, {"note": "-----BEGIN PRIVATE KEY-----"}])
def test_key_material_cannot_be_smuggled_in_and_is_never_echoed(api, config):
    response = api.client.post("/api/schedules", json={**FS, "config": config})
    assert response.status_code == 422 and error_of(response)["code"] == "invalid_config"
    assert "BEGIN" not in response.text and "private_key" not in response.text
    assert api.client.get("/api/schedules").json() == {"schedules": []}


def test_too_many_schedules_is_a_409(api):
    for _ in range(50):
        create(api, {**FS, "enabled": False})
    response = api.client.post("/api/schedules", json=FS)
    assert response.status_code == 409 and error_of(response)["code"] == "too_many_schedules"
    assert error_of(response)["details"] == {"max_schedules": 50} and len(api.client.get("/api/schedules").json()["schedules"]) == 50


# =========================================================================== list and get
def test_list_is_empty_at_first_then_oldest_first(api):
    assert api.client.get("/api/schedules").json() == {"schedules": []}
    first = create(api)
    api.clock.advance(5)
    second = create(api, TLS_PORTS)
    listed = api.client.get("/api/schedules").json()["schedules"]
    assert [s["schedule_id"] for s in listed] == [first["schedule_id"], second["schedule_id"]]
    assert listed[0] == first and listed[1] == second


def test_get_returns_one_schedule_and_404_for_an_unknown_one(api):
    view = create(api)
    got = api.client.get(f"/api/schedules/{view['schedule_id']}")
    assert got.status_code == 200 and got.json() == {"schedule": view}
    for bad in ("sched-00000000", "nope", "x" * 300):
        response = api.client.get(f"/api/schedules/{bad}")
        assert response.status_code == 404 and error_of(response)["code"] == "schedule_not_found", bad
        assert bad not in response.text
    traversal = api.client.get("/api/schedules/..%2Fsecret")                  # the encoded slash makes this no route at all
    assert traversal.status_code == 404 and "secret" not in traversal.text


def test_responses_never_carry_a_lease_a_token_or_the_raw_column_name(api):
    create(api)
    text = api.client.get("/api/schedules").text.lower()
    assert "lease" not in text and "token" not in text and "config_json" not in text


# =========================================================================== pause and resume
def test_pause_and_resume_change_only_the_enabled_state_and_the_due_time(api):
    view = create(api)
    sid = view["schedule_id"]
    api.clock.advance(10)
    paused = api.client.patch(f"/api/schedules/{sid}", json={"enabled": False})
    assert paused.status_code == 200
    assert paused.json()["schedule"] == {**view, "enabled": False, "state": "paused", "next_due_at": None}
    api.clock.advance(1000)
    resumed = api.client.patch(f"/api/schedules/{sid}", json={"enabled": True})
    assert resumed.json()["schedule"] == {**view, "next_due_at": "2026-03-01T12:17:50.000Z"}        # now (12:16:50) + 60 s, not the old due time


def test_pause_and_resume_are_idempotent(api):
    sid = create(api)["schedule_id"]
    a = api.client.patch(f"/api/schedules/{sid}", json={"enabled": False}).json()
    api.clock.advance(30)
    b = api.client.patch(f"/api/schedules/{sid}", json={"enabled": False}).json()
    assert a == b
    c = api.client.patch(f"/api/schedules/{sid}", json={"enabled": True}).json()
    api.clock.advance(30)
    d = api.client.patch(f"/api/schedules/{sid}", json={"enabled": True}).json()
    assert c == d


@pytest.mark.parametrize("body", [{}, {"enabled": "false"}, {"enabled": 0}, {"enabled": None}, {"enabled": False, "interval_seconds": 15},
                                  {"enabled": True, "config": {}}, {"interval_seconds": 15}, {"run_type": "tls"}])
def test_nothing_but_an_explicit_boolean_can_be_patched(api, body):
    view = create(api)
    response = api.client.patch(f"/api/schedules/{view['schedule_id']}", json=body)
    assert response.status_code == 422 and error_of(response)["code"] == "validation_failed"
    assert api.client.get(f"/api/schedules/{view['schedule_id']}").json() == {"schedule": view}


def test_patching_an_unknown_schedule_is_a_404(api):
    response = api.client.patch("/api/schedules/sched-00000000", json={"enabled": False})
    assert response.status_code == 404 and error_of(response)["code"] == "schedule_not_found"


def test_there_is_no_delete_and_no_put(api):
    sid = create(api)["schedule_id"]
    assert api.client.delete(f"/api/schedules/{sid}").status_code == 405
    assert api.client.put(f"/api/schedules/{sid}", json=FS).status_code == 405
    assert len(api.client.get("/api/schedules").json()["schedules"]) == 1


# =========================================================================== local-only guards
def test_the_loopback_guards_apply_to_schedules_too(api):
    sid = create(api)["schedule_id"]
    for method, path, kwargs in (("get", "/api/schedules", {}), ("post", "/api/schedules", {"json": FS}),
                                 ("patch", f"/api/schedules/{sid}", {"json": {"enabled": False}})):
        wrong_host = getattr(api.client, method)(path, headers={"Host": "evil.example"}, **kwargs)
        assert wrong_host.status_code == 403 and error_of(wrong_host)["code"] == "host_not_allowed"
        foreign = getattr(api.client, method)(path, headers={"Origin": "https://evil.example"}, **kwargs)
        assert foreign.status_code == 403 and error_of(foreign)["code"] == "origin_not_allowed"
    assert len(api.client.get("/api/schedules").json()["schedules"]) == 1
    assert api.client.get(f"/api/schedules/{sid}").json()["schedule"]["enabled"] is True


def test_the_body_size_limit_applies(tmp_path):
    api = make_api(tmp_path, max_body_bytes=2000)
    response = api.client.post("/api/schedules", json={**FS, "config": {"roots": ["C:\\" + "x" * 5000]}})
    assert response.status_code == 413 and error_of(response)["code"] == "payload_too_large"
    assert api.client.get("/api/schedules").json() == {"schedules": []}


def test_malformed_json_is_a_400(api):
    response = api.client.post("/api/schedules", content=b"{not json", headers={"Content-Type": "application/json"})
    assert response.status_code == 400 and error_of(response)["code"] == "malformed_json"


# =========================================================================== runs created through a schedule
def test_a_due_schedule_creates_a_scheduled_run_visible_through_the_runs_api(api):
    view = create(api, {**FS, "interval_seconds": 15})
    api.clock.advance(14)
    assert tick_once(api.app).created == 0 and runs_of(api) == []
    api.clock.advance(1)
    assert tick_once(api.app).created == 1
    (run,) = runs_of(api)
    assert (run["trigger"], run["schedule_id"], run["type"], run["status"]) == ("scheduled", view["schedule_id"], "filesystem", "queued")
    assert run["config"] == {"roots": ["C:\\certs"]}
    after = api.client.get(f"/api/schedules/{view['schedule_id']}").json()["schedule"]
    assert after["run_count"] == 1 and after["last_run"]["run_id"] == run["run_id"] and after["last_run"]["status"] == "queued"
    assert after["next_due_at"] == "2026-03-01T12:00:30.000Z" and after["state"] == "skipping"


def test_the_post_runs_endpoint_still_cannot_create_scheduled_runs_even_for_a_real_schedule(api):
    sid = create(api)["schedule_id"]
    for body in ({"trigger": "scheduled", "schedule_id": sid}, {"schedule_id": sid}, {"trigger": "scheduled"}):
        response = api.client.post("/api/runs", json={"type": "filesystem", **body})
        assert response.status_code == 422 and error_of(response)["code"] == "scheduled_runs_reserved"
    assert runs_of(api) == []


def test_a_scheduled_run_is_claimed_and_completed_by_the_agent_like_any_other_and_only_then_reported_completed(api):
    view = create(api, {"run_type": "filesystem", "interval_seconds": 15, "config": {"roots": ["C:\\app"]}})
    sid = view["schedule_id"]
    api.clock.advance(15)
    tick_once(api.app)
    (run,) = runs_of(api)
    agent = api.agent()
    assert agent.claim(run["run_id"]).status_code == 200
    mid = api.client.get(f"/api/schedules/{sid}").json()["schedule"]
    assert mid["last_run"]["status"] == "running" and mid["state"] == "skipping"        # NOT completed while it is running
    assert agent.upload([[0, ok_record("C:\\app\\a.pem", n=1)]]).status_code == 200
    still = api.client.get(f"/api/schedules/{sid}").json()["schedule"]
    assert still["last_run"]["status"] == "running"
    assert agent.finish(summary=summary(1)).status_code == 200
    done = api.client.get(f"/api/schedules/{sid}").json()["schedule"]
    assert done["last_run"]["status"] == "completed" and done["last_run"]["finished_at"] is not None
    assert done["state"] == "waiting" and done["run_count"] == 1
    api.clock.advance(15)
    assert tick_once(api.app).created == 1 and api.client.get(f"/api/schedules/{sid}").json()["schedule"]["run_count"] == 2


def test_a_tls_schedule_creates_a_tls_run_and_an_opted_in_one_carries_no_ports(api):
    ports = create(api, TLS_PORTS)
    api.clock.advance(30)
    tick_once(api.app)
    (run,) = runs_of(api)
    assert (run["type"], run["trigger"], run["schedule_id"], run["config"]) == ("tls", "scheduled", ports["schedule_id"], {"ports": [8443]})
    api.client.patch(f"/api/schedules/{ports['schedule_id']}", json={"enabled": False})
    broad = create(api, TLS_ALL)
    api.cancel(run["run_id"])                                                  # clear the way: the queued run would block the next one
    api.clock.advance(30)
    tick_once(api.app)
    newest = runs_of(api)[0]
    assert newest["schedule_id"] == broad["schedule_id"] and newest["config"] == {} and newest["type"] == "tls"


def test_the_schedule_list_and_the_runs_list_agree_about_the_runs_a_schedule_made(api):
    sid = create(api, {**FS, "interval_seconds": 15})["schedule_id"]
    for _ in range(3):
        api.clock.advance(15)
        tick_once(api.app)
        for run in runs_of(api):
            if run["status"] == "queued":
                api.cancel(run["run_id"])
    mine = [r for r in runs_of(api) if r["schedule_id"] == sid]
    assert len(mine) == 3 and all(r["trigger"] == "scheduled" for r in mine)
    assert api.client.get(f"/api/schedules/{sid}").json()["schedule"]["run_count"] == 3
