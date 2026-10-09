"""HTTP API, agent side: claim, lease enforcement, heartbeat, observation uploads, finish, rollback, secret hygiene."""
import hashlib
import logging
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from apifx import BASE_URL, TOKEN_HEADER, FakeClock, make_api
from backend import fs_ingest
from ingestfx import dir_error, failure_record, ok_record, pfx_record, summary

HEX32 = re.compile(r"[0-9a-f]{32}")


def error_of(response):
    body = response.json()
    assert set(body) == {"error"} and set(body["error"]) == {"code", "message", "details"}, body
    return body["error"]


def claimed(api, **create):
    run = api.create(**create)
    agent = api.agent()
    response = agent.claim(run["run_id"])
    assert response.status_code == 200, response.text
    return run["run_id"], agent


def column(api, run_id, name):
    with api.connect() as conn:
        return conn.execute(f"SELECT {name} FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0]


def count(api, table, run_id=None):
    with api.connect() as conn:
        if run_id and table in ("fs_observations", "run_issues"):
            return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id = ?", (run_id,)).fetchone()[0]
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


# =========================================================================== claim
def test_claim_hands_the_run_to_one_agent_and_issues_a_lease(api):
    run = api.create(config={"roots": ["C:\\certs"]})
    response = api.agent().claim(run["run_id"])
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    data = response.json()
    assert HEX32.fullmatch(data["lease_token"]) and set(data) == {"run", "lease_token", "lease", "limits"}
    assert data["lease"] == {"heartbeat_interval_s": 15.0, "heartbeat_timeout_s": 90.0, "finish_grace_s": 5.0}
    assert data["limits"] == {"max_batch_items": 500, "max_body_bytes": 2 * 1024 * 1024}
    claimed_run = data["run"]
    assert claimed_run["status"] == "running" and claimed_run["host_id"] == "agent-1"
    assert claimed_run["started_at"] == claimed_run["last_heartbeat_at"] == "2026-03-01T12:00:00.000Z"
    assert claimed_run["config"] == {"roots": ["C:\\certs"]}                      # the agent learns what to scan from the claim


def test_the_claiming_host_is_registered(api):
    run_id, agent = claimed(api)
    with api.connect() as conn:
        row = conn.execute("SELECT * FROM hosts").fetchone()
    assert (row["host_id"], row["hostname"], row["os"], row["agent_version"]) == ("agent-1", "WORKSTATION", "Windows 11", "0.1")
    assert column(api, run_id, "host_id") == "agent-1"


def test_only_the_hash_of_the_lease_is_stored(tmp_path):
    api = make_api(tmp_path)
    run_id, agent = claimed(api)
    assert column(api, run_id, "lease_hash") == hashlib.sha256(agent.token.encode()).hexdigest()
    with api.connect() as conn:
        dump = "\n".join(conn.iterdump())
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    raw = b"".join(open(str(api.db_path) + s, "rb").read() for s in ("", "-wal") if __import__("os").path.exists(str(api.db_path) + s))
    assert agent.token not in dump and agent.token.encode() not in raw


def test_exactly_one_claim_wins_and_the_loser_changes_nothing(api):
    run = api.create()
    first, second = api.agent(agent_id="a-1"), api.agent(agent_id="a-2")
    assert first.claim(run["run_id"]).status_code == 200
    lease_before = column(api, run["run_id"], "lease_hash")
    response = second.claim(run["run_id"])
    assert response.status_code == 409 and error_of(response)["code"] == "run_not_claimable"
    assert error_of(response)["details"]["status"] == "running" and "lease_token" not in response.text
    assert column(api, run["run_id"], "lease_hash") == lease_before and column(api, run["run_id"], "host_id") == "a-1"
    assert count(api, "hosts") == 1                                         # the loser was not even registered
    assert api.agent().claim(run["run_id"]).status_code == 409             # the same agent cannot claim twice either


def test_only_queued_runs_can_be_claimed(api):
    cancelled = api.create()
    api.cancel(cancelled["run_id"])
    finished_id, agent = claimed(api)
    agent.finish(summary=summary(0, roots=(("C:\\a", "scanned"),)))
    for run_id, status in ((cancelled["run_id"], "failed"), (finished_id, "completed")):
        response = api.agent(agent_id="late").claim(run_id)
        assert response.status_code == 409 and error_of(response)["details"]["status"] == status


def test_claiming_an_unknown_run(api):
    response = api.agent().claim("0" * 32)
    assert response.status_code == 404 and error_of(response)["code"] == "run_not_found"


def test_a_tls_run_is_not_handed_out_yet(api):
    run = api.create("tls")
    response = api.agent().claim(run["run_id"])
    assert response.status_code == 409 and error_of(response)["code"] == "unsupported_run_type"
    assert api.get(run["run_id"])["status"] == "queued" and count(api, "hosts") == 0


@pytest.mark.parametrize("body", [{}, {"hostname": "H"}, {"agent_id": "a"}, {"agent_id": "bad id!", "hostname": "H"},
                                  {"agent_id": "a" * 129, "hostname": "H"}, {"agent_id": "a", "hostname": ""},
                                  {"agent_id": "a", "hostname": "H" * 256}, {"agent_id": "a", "hostname": "-----BEGIN CERTIFICATE-----"},
                                  {"agent_id": "a", "hostname": "H", "extra": 1}, {"agent_id": 5, "hostname": "H"},
                                  {"agent_id": "a\n", "hostname": "H"}])
def test_malformed_claims_are_validation_errors_and_change_nothing(api, body):
    run = api.create()
    response = api.client.post(f"/api/runs/{run['run_id']}/claim", json=body)
    assert response.status_code == 422 and error_of(response)["code"] == "validation_failed"
    assert api.get(run["run_id"])["status"] == "queued" and count(api, "hosts") == 0


# =========================================================================== lease enforcement
@pytest.mark.parametrize("operation", ["heartbeat", "observations", "finish"])
def test_every_agent_operation_requires_the_runs_lease(api, operation):
    run_id, agent = claimed(api)
    other_id, other = claimed(api)

    def call(token):
        headers = {} if token is None else {TOKEN_HEADER: token}
        if operation == "heartbeat":
            return api.client.post(f"/api/runs/{run_id}/heartbeat", headers=headers)
        if operation == "observations":
            return api.client.post(f"/api/runs/{run_id}/observations", json={"items": [[0, ok_record(n=1)]]}, headers=headers)
        return api.client.post(f"/api/runs/{run_id}/finish", json={"outcome": "finished", "summary": None}, headers=headers)

    for bad in (None, "", "0" * 32, agent.token.upper(), agent.token + "\n", agent.token[:-1], other.token,
                hashlib.sha256(agent.token.encode()).hexdigest()):
        response = call(bad)
        assert response.status_code == 403 and error_of(response)["code"] == "invalid_lease", (operation, bad)
    assert api.get(run_id)["status"] == "running" and count(api, "fs_observations", run_id) == 0
    assert call(agent.token).status_code == 200 or operation == "finish"      # the right token works (finish checked elsewhere)


@pytest.mark.parametrize("operation", ["heartbeat", "observations", "finish"])
def test_an_unknown_run_is_a_404_for_every_agent_operation(api, operation):
    agent = api.agent()
    agent.token = "0" * 32
    response = {"heartbeat": lambda: agent.heartbeat(run_id="x" * 32), "observations": lambda: agent.upload([[0, {}]], run_id="x" * 32),
                "finish": lambda: agent.finish(run_id="x" * 32)}[operation]()
    assert response.status_code == 404 and error_of(response)["code"] == "run_not_found"


def test_a_queued_run_has_no_lease_so_no_token_is_accepted(api):
    run = api.create()
    for call in (lambda: api.client.post(f"/api/runs/{run['run_id']}/heartbeat", headers={TOKEN_HEADER: "a" * 32}),
                 lambda: api.client.post(f"/api/runs/{run['run_id']}/finish", json={"outcome": "failed"}, headers={TOKEN_HEADER: "a" * 32})):
        assert call().status_code == 403
    assert api.get(run["run_id"])["status"] == "queued"


def test_a_lease_works_only_for_its_own_run(api):
    first_id, first = claimed(api)
    second_id, second = claimed(api)
    assert first.heartbeat(run_id=second_id).status_code == 403 and second.heartbeat(run_id=first_id).status_code == 403
    assert first.heartbeat().status_code == 200 and second.heartbeat().status_code == 200


def test_the_token_header_is_the_only_credential(api):
    run_id, agent = claimed(api)
    assert api.client.post(f"/api/runs/{run_id}/heartbeat", params={"token": agent.token}).status_code == 403
    assert api.client.post(f"/api/runs/{run_id}/heartbeat", json={"lease_token": agent.token}).status_code == 403
    assert api.client.post(f"/api/runs/{run_id}/heartbeat", headers={"authorization": agent.token}).status_code == 403


# =========================================================================== heartbeat
def test_heartbeat_renews_the_lease_and_exposes_cancellation(api):
    run_id, agent = claimed(api)
    api.clock.advance(30)
    response = agent.heartbeat()
    assert response.status_code == 200
    assert response.json() == {"status": "running", "cancel_requested": False, "heartbeat_timeout_s": 90.0}
    assert api.get(run_id)["last_heartbeat_at"] == "2026-03-01T12:00:30.000Z"
    api.cancel(run_id)
    assert agent.heartbeat().json()["cancel_requested"] is True


def test_heartbeat_after_the_run_finished_is_refused(api):
    run_id, agent = claimed(api)
    assert agent.finish(summary=summary(0, roots=(("C:\\a", "scanned"),))).status_code == 200
    response = agent.heartbeat()
    assert response.status_code == 409 and error_of(response)["code"] == "run_not_running"
    assert error_of(response)["details"]["status"] == "completed"


def test_heartbeat_never_moves_the_heartbeat_backwards(api):
    run_id, agent = claimed(api)
    api.clock.advance(40)
    agent.heartbeat()
    api.clock.set(api.clock() - __import__("datetime").timedelta(seconds=25))            # a request timed earlier commits later
    agent.heartbeat()
    assert api.get(run_id)["last_heartbeat_at"] == "2026-03-01T12:00:40.000Z"


# =========================================================================== observations
def test_a_batch_is_stored_and_counted(api):
    run_id, agent = claimed(api)
    items = [[0, ok_record(r"C:\a\1.pem", n=1)], [1, failure_record(r"C:\a\locked.pem")], [2, ok_record(r"C:\a\3.pem", n=3)]]
    response = agent.upload(items)
    assert response.status_code == 200
    assert response.json() == {"accepted": 3, "duplicates": 0, "rejected": [], "conflicts": [], "status": "running", "cancel_requested": False}
    run = api.get(run_id)
    assert (run["record_count"], run["finding_count"], run["rejected_count"], run["error_count"]) == (3, 2, 0, 1)
    assert count(api, "fs_observations", run_id) == 3 and count(api, "certificates") == 2


def test_an_upload_counts_as_a_sign_of_life(api):
    run_id, agent = claimed(api)
    api.clock.advance(60)
    assert agent.upload([[0, ok_record(n=1)]]).status_code == 200
    assert api.get(run_id)["last_heartbeat_at"] == "2026-03-01T12:01:00.000Z"


def test_identical_retries_are_idempotent(api):
    run_id, agent = claimed(api)
    items = [[0, ok_record(r"C:\a\1.pem", n=1)], [1, pfx_record(r"C:\a\b.pfx", n=2)], [2, pfx_record(r"C:\a\b.pfx", n=2)]]
    first = agent.upload(items).json()
    again = agent.upload(items).json()
    assert first["accepted"] == 3 and again == {**first, "accepted": 0, "duplicates": 3}
    assert agent.upload(items).json()["duplicates"] == 3
    assert count(api, "fs_observations", run_id) == 3 and api.get(run_id)["record_count"] == 3


def test_a_partial_retry_adds_only_what_is_new(api):
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(n=1)], [1, ok_record(r"C:\a\2.pem", n=2)]])
    done = agent.upload([[0, ok_record(n=1)], [1, ok_record(r"C:\a\2.pem", n=2)], [2, ok_record(r"C:\a\3.pem", n=3)]]).json()
    assert (done["accepted"], done["duplicates"]) == (1, 2)


def test_a_conflicting_sequence_is_recorded_and_the_first_upload_stands(api):
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(r"C:\a\real.pem", n=1)]])
    done = agent.upload([[0, ok_record(r"C:\a\forged.pem", n=2)]]).json()
    assert done["conflicts"] == [0] and done["accepted"] == 0 and done["rejected"] == []
    again = agent.upload([[0, ok_record(r"C:\a\forged.pem", n=2)]]).json()
    assert again["conflicts"] == [] and again["duplicates"] == 1
    with api.connect() as conn:
        assert conn.execute("SELECT path FROM fs_observations WHERE run_id = ?", (run_id,)).fetchone()[0] == "C:\\a\\real.pem"
        assert conn.execute("SELECT COUNT(*) FROM run_issues WHERE run_id = ? AND kind = 'seq_conflict'", (run_id,)).fetchone()[0] == 1
    final = agent.finish(summary=summary(1, roots=(("C:\\a", "scanned"),)))
    assert final.json()["run"]["status"] == "partial" and final.json()["run"]["error_summary"] == "seq_conflicts:1"
    assert final.json()["run"]["rejected_count"] == 0                                 # a conflict is not an ordinary rejection


def test_bad_records_are_reported_per_record_and_do_not_stop_the_batch(api):
    run_id, agent = claimed(api)
    smuggled = ok_record(r"C:\a\2.pem", n=2)
    smuggled["der"] = "3082010a"
    done = agent.upload([[0, ok_record(n=1)], [1, smuggled], [2, {"junk": 1}], [3, ok_record(r"C:\a\4.pem", n=4, sha256="x")],
                         [4, ok_record(r"C:\a\5.pem", n=5)]]).json()
    assert done["accepted"] == 2
    assert done["rejected"] == [{"seq": 1, "code": "unknown_field"}, {"seq": 2, "code": "unknown_field"}, {"seq": 3, "code": "bad_sha256"}]
    assert "3082010a" not in str(done) and api.get(run_id)["rejected_count"] == 3


def test_raw_material_never_reaches_the_database_through_the_api(tmp_path):
    api = make_api(tmp_path)
    run_id, agent = claimed(api)
    armor = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"
    records = []
    for field in ("subject", "issuer", "path", "key_algorithm"):
        records.append(ok_record(n=1, **{field: armor}))
    records.append({**ok_record(n=2), "private_key": "abc"})
    done = agent.upload([[i, r] for i, r in enumerate(records)]).json()
    assert done["accepted"] == 0 and len(done["rejected"]) == 5
    with api.connect() as conn:
        dump = "\n".join(conn.iterdump())
    assert "PRIVATE KEY" not in dump and "private_key" not in dump.lower().replace("private_key_", "")


@pytest.mark.parametrize("items", [[[0]], [[0, {}, 1]], [[]], [["0", {}]], [[True, {}]], [[-1, {}]], [[2**31, {}]], [[1.5, {}]],
                                   [[None, {}]], [[0, {}], [1]]])
def test_malformed_items_are_refused_and_nothing_is_stored(api, items):
    run_id, agent = claimed(api)
    response = agent.upload(items)
    assert response.status_code == 422 and error_of(response)["code"] in ("bad_batch_item", "validation_failed")
    assert count(api, "fs_observations", run_id) == 0 and api.get(run_id)["last_heartbeat_at"] == api.get(run_id)["started_at"]


@pytest.mark.parametrize("body", [{}, {"items": "x"}, {"items": [{"seq": 0}]}, {"items": [], "extra": 1}, {"batch": []}])
def test_malformed_upload_bodies_are_validation_errors(api, body):
    run_id, agent = claimed(api)
    response = api.client.post(f"/api/runs/{run_id}/observations", json=body, headers=agent.headers())
    assert response.status_code == 422 and error_of(response)["code"] == "validation_failed"


def test_a_batch_over_the_item_limit_is_refused_whole(api):
    run_id, agent = claimed(api)
    items = [[i, ok_record(rf"C:\a\{i}.pem", n=i + 1)] for i in range(501)]
    response = agent.upload(items)
    assert response.status_code == 422 and error_of(response)["code"] == "batch_too_large"
    assert error_of(response)["details"] == {"max_items": 500} and count(api, "fs_observations", run_id) == 0
    assert agent.upload(items[:500]).json()["accepted"] == 500


def test_an_empty_batch_is_a_valid_sign_of_life(api):
    run_id, agent = claimed(api)
    api.clock.advance(20)
    assert agent.upload([]).json()["accepted"] == 0
    assert api.get(run_id)["last_heartbeat_at"] == "2026-03-01T12:00:20.000Z"


def test_uploads_after_the_run_finished_are_refused(api):
    run_id, agent = claimed(api)
    agent.finish(summary=summary(0, roots=(("C:\\a", "scanned"),)))
    response = agent.upload([[0, ok_record(n=1)]])
    assert response.status_code == 409 and error_of(response)["code"] == "run_not_running" and count(api, "fs_observations") == 0


# =========================================================================== finish: the backend decides
def test_a_clean_report_completes_the_run(api):
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(n=1)], [1, ok_record(r"C:\app\2.pem", n=2)]])
    response = agent.finish(summary=summary(2))
    run = response.json()["run"]
    assert response.status_code == 200 and run["status"] == "completed" and run["stop_reason"] == "completed"
    assert run["finished_at"] and run["duration_ms"] == 0 and run["error_summary"] is None
    assert run["agent_summary"]["stop_reason"] == "completed" and "errors" not in run["agent_summary"]


def test_finishing_without_a_summary_cannot_complete_a_run(api):
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(n=1)]])
    run = agent.finish(summary=None).json()["run"]
    assert run["status"] == "partial" and run["error_summary"] == "stop_reason_missing"


def test_the_agent_cannot_force_a_completed_status(api):
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(n=1)], [1, failure_record(r"C:\app\locked.pem")]])
    lying = summary(2, stop_reason="completed", complete=True, errors=[], errors_total=0)
    run = agent.finish(summary=lying).json()["run"]
    assert run["status"] == "partial" and run["error_summary"] == "file_errors:1"


def test_aggregate_counts_in_the_summary_are_never_authoritative(api):
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(n=1)], [1, ok_record(r"C:\app\2.pem", n=2)]])
    run = agent.finish(summary=summary(2, unique_certificates=999, duplicate_observations=999, files_read=999,
                                       records_by_status={"ok": 999})).json()["run"]
    assert (run["record_count"], run["finding_count"], run["rejected_count"], run["error_count"]) == (2, 2, 0, 0)
    assert run["status"] == "completed"
    wrong_total = api.agent(agent_id="x")
    other_id, other = claimed(api)
    other.upload([[0, ok_record(n=1)]])
    assert other.finish(summary=summary(50)).json()["run"]["error_summary"] == "count_mismatch"


@pytest.mark.parametrize("outcome", ["lost", "cancelled", "completed", "partial", "", None, 5])
def test_the_agent_can_only_report_that_it_finished_or_failed(api, outcome):
    run_id, agent = claimed(api)
    response = api.client.post(f"/api/runs/{run_id}/finish", json={"outcome": outcome}, headers=agent.headers())
    assert response.status_code == 422 and error_of(response)["code"] == "validation_failed"
    assert api.get(run_id)["status"] == "running"


def test_a_fatal_report_fails_the_run(api):
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(n=1)]])
    run = agent.finish(outcome="failed", fatal_code="scan_crashed").json()["run"]
    assert run["status"] == "failed" and run["error_summary"] == "scan_crashed" and run["record_count"] == 1


@pytest.mark.parametrize("code", ["Has Spaces", "x" * 41, "UPPER", "C:\\secret", "ok\n", ""])
def test_fatal_codes_are_a_fixed_vocabulary(api, code):
    run_id, agent = claimed(api)
    response = api.client.post(f"/api/runs/{run_id}/finish", json={"outcome": "failed", "fatal_code": code}, headers=agent.headers())
    assert response.status_code == 422 and api.get(run_id)["status"] == "running"


@pytest.mark.parametrize("summary_value", [{"stop_reason": "completed"}, {"roots": "x"}, {}, {"elapsed_seconds": 1}])
def test_unusable_summaries_cannot_complete_a_run(api, summary_value):
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(n=1)]])
    run = agent.finish(summary=summary_value).json()["run"]
    assert run["status"] == "partial" and run["agent_summary"] is None


def test_finish_is_not_repeatable_and_the_retry_carries_the_final_view(api):
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(n=1)]])
    first = agent.finish(summary=summary(1)).json()["run"]
    retry = agent.finish(summary=summary(1))
    assert retry.status_code == 409 and error_of(retry)["code"] == "run_already_finished"
    assert error_of(retry)["details"]["run"] == first and error_of(retry)["details"]["status"] == "completed"
    assert agent.finish(outcome="failed", fatal_code="late").json()["error"]["details"]["run"] == first     # nothing can change it


def test_finish_with_a_wrong_lease_leaves_the_run_running(api):
    run_id, agent = claimed(api)
    assert agent.finish(token="0" * 32).status_code == 403 and api.get(run_id)["status"] == "running"


# =========================================================================== failures roll back and stay quiet
@pytest.fixture
def quiet_api(tmp_path):
    api = make_api(tmp_path)
    api.client = TestClient(api.app, base_url=BASE_URL, raise_server_exceptions=False)
    return api


def test_a_database_failure_in_a_batch_rolls_back_and_exposes_nothing(quiet_api, monkeypatch):
    api = quiet_api
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(n=1)]])
    before = api.get(run_id)
    real = fs_ingest._renumber_ordinals

    def explode(*args):
        raise sqlite3.OperationalError("disk I/O error near C:\\Users\\secret\\evidence.db: SELECT * FROM runs WHERE lease_hash")
    monkeypatch.setattr(fs_ingest, "_renumber_ordinals", explode)
    response = agent.upload([[1, ok_record(r"C:\a\2.pem", n=2)], [2, ok_record(r"C:\a\3.pem", n=3)]])
    monkeypatch.setattr(fs_ingest, "_renumber_ordinals", real)
    assert response.status_code == 500 and error_of(response)["code"] == "internal_error" and error_of(response)["details"] == {}
    text = response.text.lower()
    assert not any(w in text for w in ("sqlite", "select", "secret", "evidence.db", "lease_hash", "traceback", "disk i/o"))
    assert count(api, "fs_observations", run_id) == 1 and count(api, "certificates") == 1
    assert api.get(run_id) == before                                                     # counters and heartbeat untouched
    assert agent.upload([[1, ok_record(r"C:\a\2.pem", n=2)]]).json()["accepted"] == 1   # the same upload works afterwards


def test_an_unexpected_bug_is_a_generic_500_that_rolls_back(quiet_api, monkeypatch):
    api = quiet_api
    run_id, agent = claimed(api)
    monkeypatch.setattr(fs_ingest, "derived_counts", lambda *a: (_ for _ in ()).throw(ZeroDivisionError("secret internal state")))
    response = agent.upload([[0, ok_record(n=1)]])
    assert response.status_code == 500 and "secret" not in response.text and "ZeroDivision" not in response.text
    assert count(api, "fs_observations", run_id) == 0 and count(api, "certificates") == 0


def test_a_failure_while_finishing_leaves_the_run_running_and_unchanged(quiet_api, monkeypatch):
    api = quiet_api
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(n=1)]])
    before = api.get(run_id)
    monkeypatch.setattr(fs_ingest, "_store_agent_errors", lambda *a: (_ for _ in ()).throw(sqlite3.IntegrityError("constraint")))
    response = agent.finish(summary=summary(1, errors=[dir_error()]))
    assert response.status_code == 500 and api.get(run_id) == before
    with api.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM run_issues WHERE run_id = ?", (run_id,)).fetchone()[0] == 0


def test_a_busy_database_is_a_503_with_a_retry_hint(quiet_api, monkeypatch):
    api = quiet_api
    run_id, agent = claimed(api)
    monkeypatch.setattr(fs_ingest, "ingest_fs_batch_in_tx", lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError("database is locked")))
    response = agent.upload([[0, ok_record(n=1)]])
    assert response.status_code == 503 and error_of(response)["code"] == "busy" and response.headers["retry-after"] == "1"
    assert "locked" not in response.text


def test_a_failure_while_claiming_leaves_the_run_queued(quiet_api, monkeypatch):
    api = quiet_api
    run = api.create()
    from backend import runs
    monkeypatch.setattr(runs, "start_run_in_tx", lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError("boom")))
    response = api.agent().claim(run["run_id"])
    assert response.status_code == 500 and api.get(run["run_id"])["status"] == "queued" and count(api, "hosts") == 0
    monkeypatch.undo()
    assert api.agent().claim(run["run_id"]).status_code == 200


def test_every_request_closes_its_database_connection_even_when_it_fails(quiet_api, monkeypatch):
    from backend import db

    class Recorded(sqlite3.Connection):
        instances = []

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.was_closed = False
            Recorded.instances.append(self)

        def close(self):
            self.was_closed = True
            super().close()

    real_connect = sqlite3.connect
    monkeypatch.setattr(db.sqlite3, "connect", lambda *a, **k: real_connect(*a, factory=Recorded, **k))
    api = quiet_api
    Recorded.instances.clear()
    run_id, agent = claimed(api)
    agent.heartbeat()
    agent.upload([[0, ok_record(n=1)]])
    api.client.get("/api/runs/nope")                                                   # 404 path
    agent.heartbeat(token="0" * 32)                                                    # 403 path
    monkeypatch.setattr(fs_ingest, "ingest_fs_batch_in_tx", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert agent.upload([[1, ok_record(n=2)]]).status_code == 500                      # 500 path
    assert len(Recorded.instances) >= 7
    assert [c for c in Recorded.instances if not c.was_closed] == []


# =========================================================================== secrets stay secret
def test_the_lease_token_appears_exactly_once_and_never_in_logs(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    api = make_api(tmp_path)
    run = api.create()
    agent = api.agent()
    claim = agent.claim(run["run_id"])
    token = agent.token
    responses = [claim.text]
    responses.append(agent.heartbeat().text)
    responses.append(agent.upload([[0, ok_record(n=1)]]).text)
    responses.append(api.cancel(run["run_id"]).text)
    responses.append(api.client.get(f"/api/runs/{run['run_id']}").text)
    responses.append(api.client.get("/api/runs").text)
    responses.append(agent.finish(summary=summary(1)).text)
    responses.append(agent.finish().text)
    responses.append(agent.heartbeat().text)
    bad = agent.heartbeat(token="1" * 32)
    responses.append(bad.text)
    assert [token in r for r in responses].count(True) == 1 and token in claim.text
    assert token not in caplog.text and hashlib.sha256(token.encode()).hexdigest() not in caplog.text
    assert hashlib.sha256(token.encode()).hexdigest() not in " ".join(responses)
    assert "1" * 32 not in caplog.text


def test_no_view_of_a_run_ever_contains_lease_material(api):
    run_id, agent = claimed(api)
    agent.upload([[0, ok_record(n=1)]])
    views = [api.get(run_id), api.client.get("/api/runs").json()["runs"][0], agent.finish(summary=summary(1)).json()["run"]]
    for view in views:
        assert not [k for k in view if "lease" in k or "token" in k or "hash" in k]
