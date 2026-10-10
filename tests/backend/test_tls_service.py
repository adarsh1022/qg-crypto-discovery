"""TLS runs through the HTTP protocol: claim, upload, finish, cancel, leases and expiry, with the filesystem path unchanged."""
import json

import pytest

from apifx import TOKEN_HEADER, make_api
from backend.app import sweep_once
from tlsingestfx import failed_record, peer, tls_error, tls_record, tls_summary
from ingestfx import ok_record
import ingestfx


def err(response):
    return response.json()["error"]


def new_tls_run(api, **config):
    return api.create("tls", config=config)["run_id"]


def claimed(api, run_id, **kw):
    agent = api.agent(**kw)
    assert agent.claim(run_id).status_code == 200
    return agent


# ------------------------------------------------------------------ configuration (backend checks the shape only)
@pytest.mark.parametrize("config", [
    {}, {"max_targets": 5}, {"ports": [443, 8443]}, {"connect_timeout_seconds": 1.5, "handshake_timeout_seconds": 3, "time_budget_seconds": 120},
    {"max_targets": 1024, "ports": list(range(1, 257))},
])
def test_valid_tls_configurations_are_accepted(api, config):
    assert api.client.post("/api/runs", json={"type": "tls", "config": config}).status_code == 201


@pytest.mark.parametrize("config,field", [
    ({"max_targets": 0}, "max_targets"), ({"max_targets": 1025}, "max_targets"), ({"max_targets": True}, "max_targets"),
    ({"max_targets": "5"}, "max_targets"), ({"max_targets": 2.5}, "max_targets"),
    ({"connect_timeout_seconds": 0}, "connect_timeout_seconds"), ({"connect_timeout_seconds": 31}, "connect_timeout_seconds"),
    ({"handshake_timeout_seconds": -1}, "handshake_timeout_seconds"), ({"handshake_timeout_seconds": "3"}, "handshake_timeout_seconds"),
    ({"time_budget_seconds": 3601}, "time_budget_seconds"), ({"time_budget_seconds": True}, "time_budget_seconds"),
    ({"ports": []}, "ports"), ({"ports": [0]}, "ports"), ({"ports": [65536]}, "ports"), ({"ports": ["443"]}, "ports"),
    ({"ports": [True]}, "ports"), ({"ports": "443"}, "ports"), ({"ports": list(range(1, 258))}, "ports"),
])
def test_invalid_values_of_the_known_keys_are_refused_at_creation(api, config, field):
    response = api.client.post("/api/runs", json={"type": "tls", "config": config})
    assert response.status_code == 422 and err(response)["code"] == "invalid_config" and err(response)["details"]["field"] == field


def test_the_filesystem_configuration_rules_are_unchanged(api):
    assert api.client.post("/api/runs", json={"type": "filesystem", "config": {"roots": ["C:\\x"], "bogus": 1}}).status_code == 422
    assert api.client.post("/api/runs", json={"type": "filesystem", "config": {"ports": [443]}}).status_code == 422


@pytest.mark.parametrize("config", [
    {"hosts": ["example.com"]}, {"targets": ["8.8.8.8:443"]}, {"target": "8.8.8.8"}, {"roots": ["C:\\"]}, {"note": "x"},
    {"max_targets": 5, "extra": 1}, {"ports": [443], "hosts": ["169.254.169.254"]}, {"Ports": [443]}, {"": 1},
])
def test_an_unknown_tls_key_is_rejected_at_creation_so_no_run_exists_to_claim_or_probe(api, config):
    response = api.client.post("/api/runs", json={"type": "tls", "config": config})
    assert response.status_code == 422 and err(response)["code"] == "invalid_config"
    assert err(response)["details"] == {"problem": "unknown_key", "allowed_keys": sorted(
        ["connect_timeout_seconds", "handshake_timeout_seconds", "max_targets", "ports", "time_budget_seconds"])}
    for value in config.values():                                                          # nothing the caller sent is echoed back
        for text in (value if isinstance(value, list) else [value]):
            assert not isinstance(text, str) or len(text) < 4 or text not in response.text
    assert api.client.get("/api/runs").json()["runs"] == []                                # nothing was created ...
    seen = []
    from agent.runner import poll_once
    from agentfx import make_client, options
    client, wire = make_client(api)
    assert poll_once(client, options(), tls_scan_factory=lambda *a, **k: seen.append(1)) is None   # ... so nothing can be claimed
    assert seen == [] and wire.paths("/claim") == []


def test_a_rejected_tls_configuration_leaves_no_trace(api):
    api.client.post("/api/runs", json={"type": "tls", "config": {"hosts": ["8.8.8.8"]}})
    assert api.client.get("/api/runs").json()["runs"] == [] and api.client.get("/api/runs", params={"type": "tls"}).json()["runs"] == []
    assert api.create("tls", config={"ports": [443]})["run_number"] == 1                   # run numbers are not consumed by the refusal


def test_unknown_keys_are_refused_before_known_values_are_judged(api):
    response = api.client.post("/api/runs", json={"type": "tls", "config": {"max_targets": 0, "hosts": []}})
    assert err(response)["details"]["problem"] == "unknown_key"


# ------------------------------------------------------------------ the happy path
def test_claim_upload_finish(api):
    run_id = new_tls_run(api)
    agent = api.agent()
    claim = agent.claim(run_id)
    assert claim.status_code == 200 and claim.json()["run"]["type"] == "tls" and claim.json()["run"]["status"] == "running"
    api.clock.advance(5)
    assert agent.heartbeat().status_code == 200
    records = [tls_record(1), failed_record(9000), failed_record(9001, outcome="incomplete", code="connect_timeout")]
    uploads = agent.upload_records(records, batch_size=2)
    assert all(u.status_code == 200 for u in uploads) and sum(u.json()["accepted"] for u in uploads) == 3
    api.clock.advance(5)
    final = agent.finish(summary=tls_summary(3, completed=1)).json()["run"]
    assert (final["status"], final["record_count"], final["finding_count"], final["error_count"]) == ("completed", 3, 1, 0)
    assert final["duration_ms"] == 10_000 and final["error_summary"] is None
    assert api.get(run_id)["agent_summary"]["enumeration"] == "ok"


def test_a_replayed_batch_is_idempotent_over_http(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    batch = [[0, tls_record(1)], [1, failed_record(9000)]]
    first, second = agent.upload(batch), agent.upload(batch)
    assert (first.json()["accepted"], first.json()["duplicates"]) == (2, 0) and (second.json()["accepted"], second.json()["duplicates"]) == (0, 2)
    assert api.get(run_id)["record_count"] == 2


def test_a_conflicting_replay_makes_the_run_partial_over_http(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    agent.upload([[0, tls_record(1)]])
    result = agent.upload([[0, tls_record(1, tls_version="TLS1.2")]]).json()
    assert result["conflicts"] == [0] and result["accepted"] == 0
    final = agent.finish(summary=tls_summary(1)).json()["run"]
    assert final["status"] == "partial" and "seq_conflicts:1" in final["error_summary"]


def test_rejected_records_are_reported_with_fixed_codes(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    bad = tls_record(2)
    bad["direction"] = "inbound"
    body = agent.upload([[0, tls_record(1)], [1, bad]]).json()
    assert body["accepted"] == 1 and body["rejected"] == [{"seq": 1, "code": "bad_direction"}]


def test_a_filesystem_record_sent_to_a_tls_run_is_rejected_and_a_tls_record_to_a_filesystem_run(api):
    tls_run = new_tls_run(api)
    fs_run = api.create("filesystem", config={"roots": ["C:\\x"]})["run_id"]
    tls_agent, fs_agent = claimed(api, tls_run, agent_id="a-tls"), claimed(api, fs_run, agent_id="a-fs")
    assert tls_agent.upload([[0, ok_record(n=1)]]).json()["rejected"] == [{"seq": 0, "code": "unknown_field"}]
    sent = fs_agent.upload([[0, tls_record(1)]]).json()
    assert sent["accepted"] == 0 and len(sent["rejected"]) == 1


def test_runs_of_both_types_are_ingested_side_by_side(api):
    fs_run = api.create("filesystem", config={"roots": ["C:\\app"]})["run_id"]
    tls_run = new_tls_run(api)
    fs_agent, tls_agent = claimed(api, fs_run, agent_id="a-fs"), claimed(api, tls_run, agent_id="a-tls")
    assert fs_agent.upload([[0, ok_record(n=1)]]).json()["accepted"] == 1
    sent = tls_agent.upload([[0, tls_record(2)]]).json()           # a different certificate than the filesystem record's: same sha, other facts would be refused
    assert sent["accepted"] == 1, sent
    fs_done = fs_agent.finish(summary=ingestfx.summary(1)).json()["run"]
    tls_done = tls_agent.finish(summary=tls_summary(1)).json()["run"]
    assert (fs_done["status"], fs_done["finding_count"]) == ("completed", 1)
    assert (tls_done["status"], tls_done["finding_count"]) == ("completed", 1)


def test_two_tls_runs_never_see_each_others_records(api):
    a, b = new_tls_run(api), new_tls_run(api)
    ag_a, ag_b = claimed(api, a, agent_id="a-1"), claimed(api, b, agent_id="a-2")
    ag_a.upload([[0, tls_record(1)], [1, tls_record(2, port=8444)]])
    ag_b.upload([[0, tls_record(1)]])
    assert api.get(a)["record_count"] == 2 and api.get(b)["record_count"] == 1
    assert ag_b.upload([[0, tls_record(1)]], run_id=a).status_code == 403          # b's token does not open a's run


# ------------------------------------------------------------------ leases, writes to runs that are not running
def test_a_stale_lease_is_refused(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    api.clock.advance(92)                                                           # past the 90 s heartbeat timeout, inside the 5 s grace
    response = agent.upload([[0, tls_record(1)]])
    assert response.status_code == 409 and err(response)["code"] == "lease_overdue"
    assert api.get(run_id)["record_count"] == 0
    api.clock.advance(10)                                                           # past the grace: the run has been given up on
    gone = agent.upload([[0, tls_record(1)]])
    assert gone.status_code == 409 and err(gone)["code"] == "run_not_running" and api.get(run_id)["status"] == "failed"


def test_a_wrong_or_missing_token_is_refused(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    assert agent.upload([[0, tls_record(1)]], token="0" * 32).status_code == 403
    assert api.client.post(f"/api/runs/{run_id}/observations", json={"items": []}).status_code == 403


def test_uploads_to_a_run_that_is_not_running_are_refused(api):
    queued = new_tls_run(api)
    agent = api.agent()
    assert agent.upload([[0, tls_record(1)]], run_id=queued, token="0" * 32).status_code == 403
    run_id = new_tls_run(api)
    live = claimed(api, run_id, agent_id="a-2")
    live.finish(summary=tls_summary(0))
    late = live.upload([[0, tls_record(1)]])
    assert late.status_code == 409 and err(late)["code"] in ("run_not_running", "run_already_finished")


def test_batch_limits_apply_to_tls_runs_too(tmp_path):
    api = make_api(tmp_path, max_batch_items=2)
    agent = claimed(api, new_tls_run(api))
    response = agent.upload([[i, failed_record(9000 + i)] for i in range(3)])
    assert response.status_code == 422 and err(response)["code"] == "batch_too_large"


def test_a_malformed_envelope_is_a_422_and_stores_nothing(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    response = agent.upload([[-1, tls_record(1)]])
    assert response.status_code == 422 and err(response)["code"] == "bad_batch_item" and api.get(run_id)["record_count"] == 0


# ------------------------------------------------------------------ cancellation
def test_cancel_before_claim_fails_the_run_as_cancelled(api):
    run_id = new_tls_run(api)
    assert api.cancel(run_id).status_code == 200
    run = api.get(run_id)
    assert run["status"] == "failed" and run["stop_reason"] == "cancelled"
    assert api.agent().claim(run_id).status_code == 409


def test_a_running_scan_sees_the_cancel_and_ends_partial(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    agent.upload([[0, tls_record(1)]])
    assert api.cancel(run_id).status_code == 200
    assert agent.heartbeat().json()["cancel_requested"] is True
    assert agent.upload([[1, failed_record(9000)]]).json()["cancel_requested"] is True
    final = agent.finish(summary=tls_summary(2, completed=1, stop_reason="cancelled")).json()["run"]
    assert final["status"] == "partial" and "stopped_cancelled" in final["error_summary"] and final["record_count"] == 2


def test_cancelling_a_finished_tls_run_is_refused(api):
    run_id = new_tls_run(api)
    claimed(api, run_id).finish(summary=tls_summary(0))
    assert api.cancel(run_id).status_code == 409


# ------------------------------------------------------------------ agent loss and expiry (the sweeper finalizes TLS runs too)
def test_a_lost_agent_leaves_its_evidence_and_a_partial_run(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    agent.upload([[0, tls_record(1)], [1, failed_record(9000)]])
    api.clock.advance(200)
    assert sweep_once(api.app) == 1
    run = api.get(run_id)
    assert run["status"] == "partial" and run["stop_reason"] == "agent_lost" and run["record_count"] == 2 and run["finding_count"] == 1


def test_a_lost_agent_with_nothing_recorded_fails_the_run(api):
    run_id = new_tls_run(api)
    claimed(api, run_id)
    api.clock.advance(200)
    sweep_once(api.app)
    run = api.get(run_id)
    assert run["status"] == "failed" and run["error_summary"].startswith("no_usable_data")


def test_an_unanswered_cancellation_is_enforced_for_tls_runs(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    agent.upload([[0, tls_record(1)]])
    api.cancel(run_id)
    api.clock.advance(100)
    sweep_once(api.app)
    run = api.get(run_id)
    assert run["status"] == "partial" and run["stop_reason"] == "cancelled" and run["record_count"] == 1


def test_a_queued_tls_run_nobody_claims_expires(api):
    run_id = new_tls_run(api)
    api.clock.advance(200)
    sweep_once(api.app)
    run = api.get(run_id)
    assert run["status"] == "failed" and run["stop_reason"] == "agent_not_connected"


def test_a_finish_just_after_the_heartbeat_deadline_is_still_accepted(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    agent.upload([[0, tls_record(1)]])
    api.clock.advance(92)                                                           # overdue, inside the finish grace
    final = agent.finish(summary=tls_summary(1))
    assert final.status_code == 200 and final.json()["run"]["status"] == "completed"


def test_a_fatal_failure_report_fails_the_run(api):
    run_id = new_tls_run(api)
    final = claimed(api, run_id).finish(outcome="failed", fatal_code="invalid_config").json()["run"]
    assert final["status"] == "failed" and final["error_summary"] == "invalid_config"


def test_a_repeated_finish_returns_the_final_view(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    agent.finish(summary=tls_summary(0))
    again = agent.finish(summary=tls_summary(0))
    assert again.status_code == 409 and err(again)["code"] == "run_already_finished" and err(again)["details"]["run"]["status"] == "completed"


def test_no_certificate_bytes_in_any_api_response_or_error(api):
    run_id = new_tls_run(api)
    agent = claimed(api, run_id)
    bad = tls_record(1)
    bad["pem"] = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    texts = [agent.upload([[0, bad]]).text, agent.finish(summary=tls_summary(0)).text, json.dumps(api.get(run_id))]
    assert all("BEGIN" not in t and "MIIB" not in t for t in texts)
    _ = (peer, tls_error, TOKEN_HEADER)
