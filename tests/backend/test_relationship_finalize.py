"""Recording is part of finalization: same transaction, savepoint-isolated, correct for every way a run can end, and reachable
only through the real service paths (finish, lost agent, unanswered cancellation) - plus the whole thing over HTTP."""
import logging

import pytest

import ingestfx
import relfx
from backend import db, relationships, runs
from backend.app import sweep_once
from ingestfx import ok_record, summary
from tlsingestfx import failed_record, peer, tls_error, tls_record, tls_summary


def get(api, run_id, **params):
    response = api.client.get(f"/api/runs/{run_id}/relationships", params=params)
    assert response.status_code == 200, response.text
    return response.json()


# ------------------------------------------------------------------ the hook
def test_finalizing_through_the_service_records_in_the_same_transaction(conn):
    relfx.add_host(conn)
    run_id = runs.create_run(conn, "filesystem", "manual", now=ingestfx.NOW)
    runs.start_run(conn, run_id, now=ingestfx.at(1), host_id=relfx.HOST)
    ingestfx.ingest(conn, run_id, [ok_record(r"C:\app\a.pem", 1)])
    with db.transaction(conn):
        from backend import service
        service._finalize_in_tx(conn, run_id, now=ingestfx.at(10), outcome="finished", summary=summary(1))
        assert conn.in_transaction
        assert relfx.stored(conn, run_id) == relfx.oracle_fs([ok_record(r"C:\app\a.pem", 1)])        # visible before COMMIT
    relfx.check_invariants(conn)


def test_a_rolled_back_finalization_leaves_no_relationships(conn):
    relfx.add_host(conn)
    run_id = runs.create_run(conn, "filesystem", "manual", now=ingestfx.NOW)
    runs.start_run(conn, run_id, now=ingestfx.at(1), host_id=relfx.HOST)
    ingestfx.ingest(conn, run_id, [ok_record(r"C:\app\a.pem", 1)])
    from backend import service
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            service._finalize_in_tx(conn, run_id, now=ingestfx.at(10), outcome="finished", summary=summary(1))
            raise RuntimeError("the surrounding transaction fails after recording")
    assert conn.execute("SELECT status FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0] == "running"
    assert [conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("nodes", "edges", "edge_runs")] == [0, 0, 0]


def test_a_recorder_failure_does_not_undo_the_finalization_and_is_visible_afterwards(conn, monkeypatch, caplog):
    real = relationships._node
    calls = []

    def break_after_one_node(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise sqlite_error()
        return real(*args, **kwargs)

    import sqlite3

    def sqlite_error():
        return sqlite3.OperationalError("secret SQL detail C:\\private\\path")

    monkeypatch.setattr(relationships, "_node", break_after_one_node)
    with caplog.at_level(logging.ERROR):
        run_id = relfx.fs_run(conn, [ok_record(r"C:\app\a.pem", 1)])
    assert conn.execute("SELECT status FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0] == "completed"
    assert [conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("nodes", "edges", "edge_runs")] == [0, 0, 0]   # savepoint undid the half-write
    assert not conn.in_transaction
    assert "recording relationships failed: OperationalError" in caplog.text
    assert "secret" not in caplog.text and "private" not in caplog.text                # the class only, never the message
    monkeypatch.undo()
    with db.read_snapshot(conn):
        state = relationships.get_relationships(conn, run_id)["recording"]
    assert state["state"] == "incomplete" and state["missing"] == 1                    # visible, not silently "recorded"
    assert relationships.record_run(conn, run_id) == 1                                 # and a later retry repairs it
    with db.read_snapshot(conn):
        assert relationships.get_relationships(conn, run_id)["recording"]["state"] == "recorded"


@pytest.mark.parametrize("kind", ["filesystem", "tls"])
def test_every_final_status_goes_through_the_hook(conn, kind):
    make = relfx.fs_run if kind == "filesystem" else relfx.tls_run
    record = ok_record(r"C:\app\a.pem", 1) if kind == "filesystem" else tls_record(1)
    for finish in (dict(), dict(outcome="failed", fatal_code="boom"), dict(outcome="lost"), dict(outcome="cancelled")):
        run_id = make(conn, [record], **finish)
        oracle = relfx.oracle_fs([record]) if kind == "filesystem" else relfx.oracle_tls([record])
        assert relfx.stored(conn, run_id) == oracle, finish
    relfx.check_invariants(conn)


def test_finalizing_twice_is_refused_and_changes_no_totals(conn):
    run_id = relfx.fs_run(conn, [ok_record(r"C:\app\a.pem", 1)])
    before = relfx.table_snapshot(conn)
    with pytest.raises(Exception):
        relfx.finish_in_service(conn, run_id, outcome="finished", summary=summary(1))
    assert relfx.table_snapshot(conn) == before


# ------------------------------------------------------------------ over HTTP, through the real protocol
def test_a_filesystem_run_over_http_is_recorded_and_served(api):
    run = api.create("filesystem", config={"roots": ["C:\\app"]})
    agent = api.agent()
    assert agent.claim(run["run_id"]).status_code == 200
    records = [ok_record(r"C:\app\a.pem", 1), ok_record(r"C:\app\b.pem", 1), ok_record(r"C:\app\c.pem", 2), ingestfx.failure_record()]
    assert all(r.status_code == 200 for r in agent.upload_records(records))
    assert agent.finish(summary=summary(len(records))).status_code == 200
    page = get(api, run["run_id"])
    assert page["recording"]["state"] == "recorded" and page["run"]["type"] == "filesystem"
    assert relfx.api_rows(page["items"]) == relfx.oracle_fs(records, "agent-1")
    assert page["items"][0]["target"] == {"kind": "host", "label": "WORKSTATION", "host_id": "agent-1", "sha256": None, "scope": None, "host": None}


def test_a_tls_run_over_http_is_recorded_and_served(api):
    run = api.create("tls", config={})
    agent = api.agent()
    assert agent.claim(run["run_id"]).status_code == 200
    records = [tls_record(1, port=8443, peers=[peer(1), peer(2)]), tls_record(3, port=9443), failed_record(9000)]
    assert all(r.status_code == 200 for r in agent.upload_records(records))
    assert agent.finish(summary=tls_summary(3, completed=2)).status_code == 200
    page = get(api, run["run_id"])
    assert page["recording"]["state"] == "recorded" and page["run"]["type"] == "tls"
    assert relfx.api_rows(page["items"]) == relfx.oracle_tls(records, "agent-1")
    assert page["items"][0]["process"] == {"name": "svc.exe", "exe_path": "C:\\svc\\svc.exe"}


def test_a_lost_agent_and_an_unanswered_cancellation_still_record(api):
    lost = api.create("tls", config={})["run_id"]
    agent = api.agent()
    agent.claim(lost)
    agent.upload([[0, tls_record(1)]])
    api.clock.advance(200)
    assert sweep_once(api.app) == 1
    assert api.get(lost)["status"] == "partial"
    page = get(api, lost)
    assert page["recording"]["state"] == "recorded" and page["total"] == 1

    cancelled = api.create("filesystem", config={"roots": ["C:\\app"]})["run_id"]
    other = api.agent(agent_id="agent-2", hostname="OTHER")
    other.claim(cancelled)
    other.upload([[0, ok_record(r"C:\app\a.pem", 5)]])
    api.cancel(cancelled)
    api.clock.advance(100)
    sweep_once(api.app)
    page = get(api, cancelled)
    assert page["recording"]["state"] == "recorded" and page["items"][0]["target"]["host_id"] == "agent-2"


def test_a_queued_run_nobody_claims_has_nothing_to_record(api):
    run_id = api.create("tls", config={})["run_id"]
    assert get(api, run_id)["recording"]["state"] == "pending"
    api.clock.advance(200)
    sweep_once(api.app)
    page = get(api, run_id)
    assert api.get(run_id)["status"] == "failed" and page["recording"]["state"] == "none_expected" and page["items"] == []


def test_repeated_scans_over_http_report_cross_run_strength(api):
    totals = []
    for _ in range(3):
        run = api.create("filesystem", config={"roots": ["C:\\app"]})
        agent = api.agent()
        agent.claim(run["run_id"])
        agent.upload_records([ok_record(r"C:\app\a.pem", 1)])
        agent.finish(summary=summary(1))
        item = get(api, run["run_id"])["items"][0]
        totals.append((item["in_run"]["observations"], item["all_runs"]["observations"], item["all_runs"]["runs"]))
    assert totals == [(1, 1, 1), (1, 2, 2), (1, 3, 3)]
    first = get(api, api.client.get("/api/runs?limit=100").json()["runs"][-1]["run_id"])["items"][0]
    assert first["in_run"]["observations"] == 1 and first["all_runs"]["runs"] == 3          # an earlier run reads its own contribution only
