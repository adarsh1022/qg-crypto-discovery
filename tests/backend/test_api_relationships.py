"""GET /api/runs/{run_id}/relationships: the contract (read-only, bounded, validated, no-store, allow-listed fields)."""
import pytest

import ingestfx
import relfx
from backend import db
from ingestfx import ok_record, summary
from tlsingestfx import peer, tls_record, tls_summary


def error(response):
    return response.json()["error"]


def seeded(api, kind="filesystem", n=3):
    run = api.create(kind, config={"roots": ["C:\\app"]} if kind == "filesystem" else {})
    agent = api.agent()
    agent.claim(run["run_id"])
    if kind == "filesystem":
        agent.upload_records([ok_record(rf"C:\app\f{i}.pem", i) for i in range(1, n + 1)])
        agent.finish(summary=summary(n))
    else:
        agent.upload_records([tls_record(100 + i, port=8000 + i) for i in range(1, n + 1)])   # other certificates than the filesystem ones
        agent.finish(summary=tls_summary(n, completed=n))
    return run["run_id"]


def test_the_response_shape_and_headers(api):
    run_id = seeded(api)
    response = api.client.get(f"/api/runs/{run_id}/relationships")
    assert response.status_code == 200 and "no-store" in response.headers["cache-control"]
    body = response.json()
    assert set(body) == {"run", "recording", "counts", "items", "total", "limit", "truncated"}
    assert set(body["run"]) == {"run_id", "run_number", "type", "status", "final"}
    assert set(body["recording"]) == {"state", "expected", "recorded", "missing", "unexpected"}
    assert body["limit"] == 200 and body["total"] == 3 and body["truncated"] is False
    item = body["items"][0]
    assert set(item) == {"kind", "label", "source", "target", "in_run", "all_runs", "process", "filesystem_evidence"}
    assert set(item["in_run"]) == {"observations", "first_at", "last_at"}
    assert set(item["all_runs"]) == {"observations", "runs", "first_seen_at", "last_seen_at"}


def test_a_tls_row_publishes_the_listener_and_the_process_but_no_pid_or_internal_id(api):
    run_id = seeded(api, "tls", 1)
    text = api.client.get(f"/api/runs/{run_id}/relationships").text
    assert '"scope":"local_listener"' in text.replace(" ", "")
    assert "4321" not in text                                           # the fixture PID
    for forbidden in ("edge_id", "node_id", "pid", "communicates_with", "lease", "BEGIN"):
        assert forbidden not in text, forbidden


def test_both_run_types_are_served(api):
    for kind in ("filesystem", "tls"):
        body = api.client.get(f"/api/runs/{seeded(api, kind)}/relationships").json()
        assert body["run"]["type"] == kind and body["recording"]["state"] == "recorded"


def test_an_unknown_run_is_404(api):
    response = api.client.get("/api/runs/does-not-exist/relationships")
    assert response.status_code == 404 and error(response)["code"] == "run_not_found" and "no-store" in response.headers["cache-control"]


@pytest.mark.parametrize("query", ["limit=0", "limit=501", "limit=abc", "limit=-1", "limit=", "limit=1&limit=2", "offset=1", "frontier=3", "x=1"])
def test_bad_queries_are_422_and_never_echoed(api, query):
    run_id = seeded(api)
    response = api.client.get(f"/api/runs/{run_id}/relationships?{query}")
    assert response.status_code == 422 and error(response)["code"] == "validation_failed"
    assert "abc" not in response.text and "no-store" in response.headers["cache-control"]


def test_limit_bounds_the_page_and_reports_truncation(api):
    run_id = seeded(api, n=7)
    body = api.client.get(f"/api/runs/{run_id}/relationships?limit=2").json()
    assert len(body["items"]) == 2 and body["total"] == 7 and body["truncated"] is True and body["limit"] == 2
    assert api.client.get(f"/api/runs/{run_id}/relationships?limit=500").json()["truncated"] is False


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_it_is_read_only(api, method):
    run_id = seeded(api)
    response = getattr(api.client, method)(f"/api/runs/{run_id}/relationships")
    assert response.status_code in (404, 405)


def test_reading_changes_nothing_in_the_database(api):
    run_id = seeded(api, n=4)
    conn = api.connect()
    before = relfx.table_snapshot(conn)
    runs_before = conn.execute("SELECT * FROM runs ORDER BY run_id").fetchall()
    for _ in range(3):
        api.client.get(f"/api/runs/{run_id}/relationships")
        api.client.get(f"/api/runs/{run_id}/relationships?limit=1")
    assert relfx.table_snapshot(conn) == before and conn.execute("SELECT * FROM runs ORDER BY run_id").fetchall() == runs_before
    conn.close()


def test_an_older_run_without_records_is_reported_as_not_recorded_not_as_empty(api):
    run_id = seeded(api)
    conn = api.connect()
    with db.transaction(conn):                    # make the run look like one finalized before relationship recording existed
        conn.execute("DELETE FROM edge_runs")
        conn.execute("DELETE FROM edges")
        conn.execute("DELETE FROM nodes")
    conn.close()
    body = api.client.get(f"/api/runs/{run_id}/relationships").json()
    assert body["recording"] == {"state": "incomplete", "expected": 3, "recorded": 0, "missing": 3, "unexpected": 0}
    assert body["items"] == [] and body["total"] == 0


def test_the_other_endpoints_are_unchanged(api):
    run_id = seeded(api)
    assert api.client.get(f"/api/runs/{run_id}").status_code == 200
    assert api.client.get(f"/api/runs/{run_id}/fs/summary").status_code == 200
    assert api.client.get(f"/api/runs/{run_id}/relationships/extra").status_code == 404
