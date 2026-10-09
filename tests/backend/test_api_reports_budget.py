"""The report time budget: settings, the 503 envelope, cleanup after a timeout or any other failure, the deadline during
Python work, and a cumulative budget across statements."""
import datetime as dt
import math
import random
import sqlite3
import time

import pytest

import reportfx
from apifx import make_api
from backend import db, reports, summaries
from backend.db import QueryBudget, QueryTimeout
from backend.settings import MAX_QUERY_BUDGET_S, Settings
from reportapifx import all_report_urls, seed

NOW = dt.datetime(2026, 3, 1, 12, tzinfo=dt.timezone.utc)
HEAVY = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 30000) SELECT COUNT(*) FROM c"


class Runaway:
    """A monotonic clock that stands still, then (when `running_away`) jumps 1000 s on every reading."""

    def __init__(self):
        self.now, self.running_away = 0.0, False

    def __call__(self) -> float:
        if self.running_away:
            self.now += 1000.0
        return self.now


class Manual:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


# =========================================================================== settings
def test_the_default_budget_is_five_seconds(tmp_path):
    assert Settings(db_path=tmp_path / "x.db").query_budget_s == 5.0


@pytest.mark.parametrize("value", [0.001, 1, 5, 299.999, 300, 300.0])
def test_budgets_in_range_are_accepted(tmp_path, value):
    assert Settings(db_path=tmp_path / "x.db", query_budget_s=value).query_budget_s == value


@pytest.mark.parametrize("value", [0, 0.0, -1, -0.5, 300.001, 301, 10**6, math.inf, -math.inf, math.nan, True, False, "5", "", None, [5], (5,), {"s": 5}])
def test_budgets_out_of_range_or_of_the_wrong_type_are_refused(tmp_path, value):
    with pytest.raises(ValueError):
        Settings(db_path=tmp_path / "x.db", query_budget_s=value)


def test_the_maximum_is_three_hundred_seconds():
    assert MAX_QUERY_BUDGET_S == 300


def test_the_app_uses_the_monotonic_clock_unless_told_otherwise(tmp_path):
    assert make_api(tmp_path).app.state.budget_clock is time.monotonic


# =========================================================================== QueryBudget.check and the handler
def test_check_is_silent_within_the_deadline_and_raises_after_it():
    clock = Manual()
    budget = QueryBudget(5, clock=clock)
    budget.check()
    clock.now = 5.0
    budget.check()                                                     # exactly at the deadline is still inside it
    assert budget.expired is False
    clock.now = 5.001
    with pytest.raises(QueryTimeout):
        budget.check()
    assert budget.expired is True
    with pytest.raises(QueryTimeout):                                  # and it stays expired
        budget.check()


def test_a_broken_clock_fails_closed_in_check_and_in_the_handler(conn):
    class Breaks:
        calls = 0

        def __call__(self):
            Breaks.calls += 1
            if Breaks.calls > 1:
                raise RuntimeError("clock failure with SECRET text")
            return 0.0
    budget = QueryBudget(5, clock=Breaks())
    with pytest.raises(QueryTimeout):
        budget.check()
    Breaks.calls = 0
    budget = QueryBudget(5, clock=Breaks(), check_every=100)
    with pytest.raises(QueryTimeout) as caught:                       # the handler's failure cannot escape as a RuntimeError
        with db.read_snapshot(conn, budget):
            conn.execute(HEAVY).fetchall()
    assert "SECRET" not in str(caught.value) and caught.value.__cause__ is None
    assert not conn.in_transaction
    assert conn.execute("SELECT 1").fetchone()[0] == 1


def test_the_budget_is_cumulative_across_statements_of_one_snapshot(conn):
    clock = Manual()
    budget = QueryBudget(5, clock=clock, check_every=100)
    with pytest.raises(QueryTimeout):
        with db.read_snapshot(conn, budget):
            assert conn.execute(HEAVY).fetchone()[0] == 30000          # t = 0: fine
            clock.now = 4.0
            assert conn.execute(HEAVY).fetchone()[0] == 30000          # t = 4: still inside the 5 s
            clock.now = 6.0
            conn.execute(HEAVY).fetchone()                             # t = 6: the third statement is stopped
    assert not conn.in_transaction


# =========================================================================== the deadline during Python work
@pytest.fixture
def many_certificates(conn):
    records = [reportfx.cert(rf"C:\m\c{n}.pem", n, r"C:\m") for n in range(1, 601)]
    return conn, reportfx.load(conn, records, batch=100)


class CountingBudget:
    """Stands in for a QueryBudget: counts check() calls and raises on a chosen one."""

    def __init__(self, raise_on=None):
        self.calls, self.raise_on = 0, raise_on

    def check(self):
        self.calls += 1
        if self.raise_on == self.calls:
            raise QueryTimeout("budget")


def summary_calls(conn, run_id, budget):
    with db.read_snapshot(conn):
        return summaries.fs_summary(conn, run_id, now=NOW, budget=budget)


def test_the_validity_loop_checks_the_deadline_every_256_certificates(many_certificates, conn):
    conn, run_id = many_certificates
    small = reportfx.load(conn, [reportfx.cert(r"C:\s\one.pem", 1, r"C:\s")])
    for_one, for_many = CountingBudget(), CountingBudget()
    summary_calls(conn, small, for_one)
    summary_calls(conn, run_id, for_many)
    assert summaries.CHECK_EVERY == 256
    assert for_many.calls - for_one.calls == 2                         # 600 certificates: checks at rows 0, 256, 512 instead of row 0


def test_a_deadline_that_passes_inside_the_loop_stops_the_summary_there(many_certificates):
    conn, run_id = many_certificates
    budget = CountingBudget(raise_on=2)                                # the second check is the one at row 256, inside the loop
    with pytest.raises(QueryTimeout):
        summary_calls(conn, run_id, budget)
    assert budget.calls == 2 and not conn.in_transaction


def test_python_work_is_stopped_even_when_sqlites_own_handler_can_never_fire(many_certificates):
    conn, run_id = many_certificates
    clock = Runaway()
    budget = QueryBudget(5, clock=clock, check_every=10**9)            # SQLite would call the handler once in a billion steps
    clock.running_away = True
    with pytest.raises(QueryTimeout):
        with db.read_snapshot(conn, budget):
            summaries.fs_summary(conn, run_id, now=NOW, budget=budget)
    assert not conn.in_transaction


def test_a_summary_within_budget_is_identical_with_and_without_one(many_certificates):
    conn, run_id = many_certificates
    clock = Manual()
    with_budget = summary_calls(conn, run_id, QueryBudget(5, clock=clock))
    assert with_budget == summary_calls(conn, run_id, None)


def test_the_dashboard_passes_its_budget_to_the_summary(conn):
    reportfx.load(conn, [reportfx.cert(r"C:\s\one.pem", 1, r"C:\s")])
    run = conn.execute("SELECT run_id FROM runs").fetchone()[0]
    conn.execute("UPDATE runs SET status = 'completed', finished_at = '2026-03-01T12:00:10.000Z', duration_ms = 9000, "
                 "stop_reason = 'completed' WHERE run_id = ?", (run,))
    budget = CountingBudget()
    with db.read_snapshot(conn):
        summaries.dashboard(conn, now=NOW, budget=budget)
    assert budget.calls >= 3


# =========================================================================== the 503 over HTTP
@pytest.fixture
def runaway_api(tmp_path):
    clock = Runaway()
    api = make_api(tmp_path, budget_clock=clock)
    records = reportfx.random_records(random.Random(7), 400, cert_count=60, path_count=6)
    run_id = seed(api, records, state="running")
    seed(api, reportfx.build_records()[:6])                      # a finished run, so the dashboard has a summary to compute
    return api, run_id, clock


def timeout_urls(run_id):
    return [f"/api/runs/{run_id}/fs/summary", "/api/dashboard", f"/api/runs/{run_id}/fs/observations?sort=path&q=host",
            f"/api/runs/{run_id}/fs/certificates?sort=subject&q=host"]


def test_the_timeout_answer_is_exactly_the_agreed_envelope(runaway_api):
    api, run_id, clock = runaway_api
    clock.running_away = True
    for url in timeout_urls(run_id):
        response = api.client.get(url)
        assert response.status_code == 503, (url, response.text)
        assert response.json() == {"error": {"code": "query_timeout",
                                             "message": "The request took too long and was stopped. Narrow the filters and try again.",
                                             "details": {"budget_seconds": 5.0}}}
        assert response.headers["retry-after"] == "1" and response.headers["cache-control"] == "no-store"
        assert response.headers["content-type"].startswith("application/json")


def test_the_budget_seconds_follow_the_setting(tmp_path):
    clock = Runaway()
    api = make_api(tmp_path, budget_clock=clock, query_budget_s=2.5)
    run_id = seed(api, reportfx.build_records()[:5], state="running")
    clock.running_away = True
    assert api.client.get(f"/api/runs/{run_id}/fs/summary").json()["error"]["details"] == {"budget_seconds": 2.5}


class Ticking:
    """A clock that moves a fixed step on every reading."""

    def __init__(self, step):
        self.now, self.step = 0.0, step

    def __call__(self):
        self.now += self.step
        return self.now


def test_the_configured_budget_decides_when_a_request_times_out(tmp_path):
    records = reportfx.build_records()[:10]
    tight = make_api(tmp_path, name="tight.db", budget_clock=Ticking(0.05), query_budget_s=0.1)
    loose = make_api(tmp_path, name="loose.db", budget_clock=Ticking(0.05), query_budget_s=300)
    for api in (tight, loose):
        run_id = seed(api, records)
        outcome = api.client.get(f"/api/runs/{run_id}/fs/summary").status_code
        assert outcome == (503 if api is tight else 200)


def test_a_failed_validation_opens_no_connection(api, recorded):
    run_id = seed(api, reportfx.build_records()[:3])
    recorded.instances.clear()
    for url in (f"/api/runs/{run_id}/fs/observations?limit=0", f"/api/runs/{run_id}/fs/observations?bogus=1", "/api/meta?x=1",
                f"/api/runs/{run_id}/fs/certificates?sort=first_seq"):
        assert api.client.get(url).status_code == 422
    assert recorded.instances == []                                    # refused before any connection was opened


def test_the_error_reveals_nothing_about_the_query(runaway_api):
    api, run_id, clock = runaway_api
    clock.running_away = True
    response = api.client.get(f"/api/runs/{run_id}/fs/observations?q=SECRETNEEDLE&sort=path")
    assert response.status_code == 503
    for word in ("SECRETNEEDLE", "SELECT", "fs_observations", "interrupted", "Traceback", run_id):
        assert word not in response.text


@pytest.fixture
def recorded(monkeypatch):
    class Recorded(sqlite3.Connection):
        instances = []

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.was_closed, self.open_transaction_at_close = False, None
            Recorded.instances.append(self)

        def close(self):
            self.open_transaction_at_close = self.in_transaction
            self.was_closed = True
            super().close()

    real = sqlite3.connect
    monkeypatch.setattr(db.sqlite3, "connect", lambda *a, **k: real(*a, factory=Recorded, **k))
    Recorded.instances.clear()
    return Recorded


def assert_clean(recorded):
    assert recorded.instances
    assert [c for c in recorded.instances if not c.was_closed] == []
    assert [c for c in recorded.instances if c.open_transaction_at_close] == []


def test_a_timeout_closes_every_connection_and_leaves_no_transaction_open(runaway_api, recorded):
    api, run_id, clock = runaway_api
    recorded.instances.clear()
    clock.running_away = True
    for url in timeout_urls(run_id):
        assert api.client.get(url).status_code == 503
    assert len(recorded.instances) == 4
    assert_clean(recorded)


def test_a_writer_can_write_immediately_after_a_timeout(runaway_api):
    api, run_id, clock = runaway_api
    clock.running_away = True
    assert api.client.get(f"/api/runs/{run_id}/fs/observations?sort=path&q=host").status_code == 503
    writer = db.connect(api.db_path, busy_timeout_ms=0)                # no waiting allowed: any lock left behind would fail this
    try:
        with db.transaction(writer):
            writer.execute("INSERT INTO meta (key, value) VALUES ('after-timeout', '1')")
        assert writer.execute("SELECT value FROM meta WHERE key = 'after-timeout'").fetchone()[0] == "1"
    finally:
        writer.close()
    assert api.client.post("/api/runs", json={"type": "tls"}).status_code == 201     # and so can the API itself


def test_the_next_request_succeeds_after_a_timeout(runaway_api):
    api, run_id, clock = runaway_api
    clock.running_away = True
    assert api.client.get(f"/api/runs/{run_id}/fs/summary").status_code == 503
    clock.running_away = False
    for url in [*timeout_urls(run_id), *all_report_urls(run_id)[:3]]:
        assert api.client.get(url).status_code == 200, url


def test_a_timeout_does_not_poison_a_concurrent_or_following_reader(runaway_api):
    api, run_id, clock = runaway_api
    clock.running_away = True
    assert api.client.get(f"/api/runs/{run_id}/fs/summary").status_code == 503
    clock.running_away = False
    fresh = api.client.get(f"/api/runs/{run_id}/fs/summary").json()
    assert fresh["totals"]["records"] == 400


# =========================================================================== other failures clean up too
@pytest.mark.parametrize("failure,status,code", [
    (sqlite3.OperationalError("disk I/O error with SECRET text"), 500, "internal_error"),
    (sqlite3.DatabaseError("malformed database SECRET"), 500, "internal_error"),
    (sqlite3.OperationalError("database is locked"), 503, "busy"),
    (RuntimeError("boom SECRET"), 500, "internal_error"),
    (ValueError("SECRET"), 500, "internal_error")])
def test_other_failures_are_safe_no_store_and_clean(api, recorded, monkeypatch, caplog, failure, status, code):
    run_id = seed(api, reportfx.build_records()[:5])
    recorded.instances.clear()

    def explode(*args, **kwargs):
        raise failure
    monkeypatch.setattr(reports, "search_sightings", explode)
    response = api.client.get(f"/api/runs/{run_id}/fs/observations")
    assert response.status_code == status and response.json()["error"]["code"] == code
    assert "SECRET" not in response.text and response.headers["cache-control"] == "no-store"
    assert "SECRET" not in " ".join(r.getMessage() for r in caplog.records if r.name.startswith("backend"))        # nor in the logs
    if code == "busy":
        assert response.headers["retry-after"] == "1"
    assert_clean(recorded)
    monkeypatch.undo()
    assert api.client.get(f"/api/runs/{run_id}/fs/observations").status_code == 200


def test_successful_requests_also_close_their_connection(api, recorded):
    run_id = seed(api, reportfx.build_records()[:5])
    recorded.instances.clear()
    for url in all_report_urls(run_id):
        api.client.get(url)
    assert len(recorded.instances) == len(all_report_urls(run_id))
    assert_clean(recorded)


def test_report_connections_are_read_only(api, monkeypatch):
    run_id = seed(api, reportfx.build_records()[:5])
    seen = []

    def try_to_write(conn, run_id_, query=None):
        try:
            conn.execute("INSERT INTO meta (key, value) VALUES ('sneaky', '1')")
        except sqlite3.Error as exc:
            seen.append(str(exc))
            raise
    monkeypatch.setattr(reports, "search_sightings", try_to_write)
    response = api.client.get(f"/api/runs/{run_id}/fs/observations")
    assert response.status_code == 500 and seen and "readonly" in seen[0]
    conn = api.connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM meta WHERE key = 'sneaky'").fetchone()[0] == 0
    finally:
        conn.close()


# =========================================================================== a response that does not fit its model
LEAKY = {"SECRETKEY": r"SECRETVALUE with a path C:\Users\SECRET\key.pem"}


def force_bad_data(monkeypatch, name):
    """Make one report endpoint's data layer return something its response model cannot accept."""
    from backend import summaries
    if name == "meta":
        monkeypatch.setattr(db, "data_origin", lambda conn: LEAKY)
    elif name == "dashboard":
        monkeypatch.setattr(summaries, "dashboard", lambda *a, **k: LEAKY)
    elif name == "stats":
        monkeypatch.setattr(summaries, "run_statistics", lambda *a, **k: {"by_type_status": [LEAKY], "series": [LEAKY]})
    elif name == "summary":
        monkeypatch.setattr(summaries, "fs_summary", lambda *a, **k: LEAKY)
    elif name == "observations":
        monkeypatch.setattr(reports, "search_sightings", lambda *a, **k: reports.Page([LEAKY], 1, 100, 0, 1))
    elif name == "certificates":
        monkeypatch.setattr(reports, "search_unique_certificates", lambda *a, **k: reports.Page([LEAKY], 1, 100, 0, 1))
    elif name == "issues":
        monkeypatch.setattr(reports, "list_issues", lambda *a, **k: LEAKY)
    else:
        monkeypatch.setattr(reports, "certificate_detail", lambda *a, **k: LEAKY)


URLS = {"meta": "/api/meta", "dashboard": "/api/dashboard", "stats": "/api/runs/stats", "summary": "/api/runs/{run}/fs/summary",
        "observations": "/api/runs/{run}/fs/observations", "certificates": "/api/runs/{run}/fs/certificates",
        "issues": "/api/runs/{run}/issues", "certificate": "/api/certificates/" + "1".zfill(64)}


@pytest.mark.parametrize("name", list(URLS))
def test_a_response_that_does_not_fit_its_model_is_a_generic_no_store_500(api, recorded, monkeypatch, caplog, name):
    run_id = seed(api, reportfx.build_records()[:5])
    seed(api, reportfx.build_records()[:3])                                    # so the dashboard has a finished run to summarise
    recorded.instances.clear()
    force_bad_data(monkeypatch, name)
    response = api.client.get(URLS[name].format(run=run_id))                  # the test client re-raises server exceptions: none escapes
    assert response.status_code == 500
    assert response.json() == {"error": {"code": "internal_error", "message": "Something went wrong on the server.", "details": {}}}
    assert response.headers["cache-control"] == "no-store" and response.headers["content-type"].startswith("application/json")
    for leaked in ("SECRET", "key.pem", "Users", "ResponseValidationError", "pydantic", "Field required", "input_value"):
        assert leaked not in response.text, leaked
    backend_logs = " ".join(r.getMessage() for r in caplog.records if r.name.startswith("backend"))
    assert "SECRET" not in backend_logs and "key.pem" not in backend_logs
    # pin the layer: ReportRoute's guard handled this (serve() would have logged "unhandled error: ..." or "database error: ...")
    assert [r.getMessage() for r in caplog.records if r.name == "backend.api"] == ["report response failed validation: ResponseValidationError"]
    assert [c for c in recorded.instances if not c.was_closed] == []           # the connection was closed before the model check
    monkeypatch.undo()
    assert api.client.get(URLS[name].format(run=run_id)).status_code == 200                                  # the next request is unaffected


def test_the_validation_guard_applies_to_the_report_routes_only(api, monkeypatch):
    """A mismatch on any other route keeps the application-wide behavior: the generic envelope, and no report-specific header."""
    from fastapi.routing import APIRoute
    from fastapi.testclient import TestClient
    from apifx import BASE_URL
    from backend import service
    from backend.report_routes import ReportRoute
    monkeypatch.setattr(service, "list_runs", lambda *a, **k: [{"SECRETKEY": "SECRETVALUE"}])
    quiet = TestClient(api.app, base_url=BASE_URL, raise_server_exceptions=False)
    response = quiet.get("/api/runs")
    assert response.status_code == 500 and response.json()["error"]["code"] == "internal_error"
    assert "SECRET" not in response.text and response.headers.get("cache-control") is None
    from test_api_reports_contract import app_routes_in_order
    classes = {route.path: type(route) for route in app_routes_in_order(api.app)}
    assert classes["/api/runs"] is APIRoute and classes["/api/runs/{run_id}"] is APIRoute
    assert all(cls is ReportRoute for path, cls in classes.items() if path in {"/api/meta", "/api/dashboard", "/api/runs/stats"})
