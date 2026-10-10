"""The report endpoints over HTTP: correctness against the independent oracle, the run-state and run-type matrix, the
local-only guards, no-store, reads that change nothing, and an end-to-end run from a fake agent to the report."""
import logging

import pytest

import reportfx
from apifx import START, make_api
from backend import runs
from ingestfx import dir_error, sha, summary
from reportapifx import GLOBAL_URLS, RUN_SCOPED, all_report_urls, dump, run_scoped_urls, seed

NO_STORE = "no-store"


def get(api, url, **kwargs):
    response = api.client.get(url, **kwargs)
    assert response.headers.get("cache-control") == NO_STORE, (url, response.status_code, response.headers)
    return response


def ok(api, url, **kwargs):
    response = get(api, url, **kwargs)
    assert response.status_code == 200, (url, response.text)
    return response.json()


def error_of(response):
    body = response.json()
    assert set(body) == {"error"} and set(body["error"]) == {"code", "message", "details"}, body
    return body["error"]


@pytest.fixture
def seeded(api):
    records = reportfx.build_records()
    return api, seed(api, records), records


# =========================================================================== meta
def test_meta_reports_the_database_origin_schema_and_server_time(api):
    body = ok(api, "/api/meta")
    assert body == {"data_origin": "agent", "schema_version": 3, "server_time": "2026-03-01T12:00:00.000Z"}
    api.clock.advance(61.5)
    assert ok(api, "/api/meta")["server_time"] == "2026-03-01T12:01:01.500Z"


def test_meta_reads_the_origin_from_the_database_not_from_the_settings(tmp_path):
    from backend import db
    path = tmp_path / "s.db"
    db.open_database(path, "sample").close()
    api = make_api(tmp_path, name="s.db", data_origin="sample")
    assert ok(api, "/api/meta")["data_origin"] == "sample"


# =========================================================================== inventory against the oracle
SIGHTING_FIELDS = ["seq", "entry_ordinal", "path", "filename", "scan_root", "format", "discovered_at", "sha256", "chain_index",
                   "chain_total", "chain_role", "parse_status", "detail", "access_error", "evidence_confidence", "validity_status",
                   "days_to_expiry", "duplicate_kind", "serial_hex", "subject", "issuer", "san", "key_algorithm", "key_size",
                   "key_curve", "signature_algorithm", "not_before", "not_after", "warnings"]


def test_the_observation_inventory_matches_the_oracle_field_by_field(seeded):
    api, run_id, records = seeded
    body = ok(api, f"/api/runs/{run_id}/fs/observations?limit=500")
    expected = reportfx.sightings(records)
    assert body["total"] == len(records) == len(body["items"]) and body["limit"] == 500 and body["offset"] == 0
    for item, row in zip(body["items"], expected):
        assert {k: item[k] for k in SIGHTING_FIELDS} == {k: row[k] for k in SIGHTING_FIELDS}
        assert item["owning_process"] is None


@pytest.mark.parametrize("query,filters", [
    ("parse_status=ok", dict(parse_status="ok")), ("parse_status=access_denied", dict(parse_status="access_denied")),
    ("validity_status=expired", dict(validity_status="expired")), ("format=pkcs12", dict(format="pkcs12")),
    ("chain_role=leaf", dict(chain_role="leaf")), ("evidence_confidence=medium", dict(evidence_confidence="medium")),
    ("duplicate_kind=across_files", dict(duplicate_kind="across_files")), ("duplicate_kind=within_file", dict(duplicate_kind="within_file")),
    ("key_algorithm=RSA&key_size=2048", dict(key_algorithm="RSA", key_size=2048)), ("has_warnings=true", dict(has_warnings=True)),
    ("issuer=CN%3DAlpha%20CA", dict(issuer="CN=Alpha CA")), ("scan_root=D%3A%5Cdata", dict(scan_root=r"D:\data")),
    ("q=100%25", dict(q="100%")), ("q=A_B", dict(q="A_B")), ("q=host", dict(q="host")), ("q=%C3%A9cole", dict(q="école")),
    ("fingerprint=0000000000000000000000000000000000000000000000000000000000000001", dict(fingerprint=sha(1))),
    ("fingerprint=0000", dict(fingerprint="0000"))])
def test_filters_over_http_match_the_oracle(seeded, query, filters):
    api, run_id, records = seeded
    body = ok(api, f"/api/runs/{run_id}/fs/observations?limit=500&{query}")
    expected = reportfx.sightings(records, **filters)
    assert [i["seq"] for i in body["items"]] == [r["seq"] for r in expected] and body["total"] == len(expected)


@pytest.mark.parametrize("sort", ["seq", "path", "filename", "scan_root", "format", "discovered_at", "parse_status", "validity_status",
                                  "days_to_expiry", "evidence_confidence", "subject", "issuer", "key_algorithm", "key_size",
                                  "signature_algorithm", "not_after", "duplicate_kind"])
@pytest.mark.parametrize("direction", ["asc", "desc"])
def test_every_published_sort_works_and_matches_the_oracle(seeded, sort, direction):
    api, run_id, records = seeded
    body = ok(api, f"/api/runs/{run_id}/fs/observations?limit=500&sort={sort}&direction={direction}")
    assert [i["seq"] for i in body["items"]] == [r["seq"] for r in reportfx.sightings(records, sort=sort, direction=direction)]


def test_paging_with_a_frontier_walks_the_whole_inventory_exactly_once(seeded):
    api, run_id, records = seeded
    first = ok(api, f"/api/runs/{run_id}/fs/observations?limit=5&sort=path")
    frontier = first["frontier"]
    seen, offset = [], 0
    while offset < first["total"]:
        page = ok(api, f"/api/runs/{run_id}/fs/observations?limit=5&offset={offset}&sort=path&frontier={frontier}")
        assert page["frontier"] == frontier and page["total"] == first["total"]
        seen += [i["seq"] for i in page["items"]]
        offset += 5
    assert seen == [r["seq"] for r in reportfx.sightings(records, sort="path")]
    assert ok(api, f"/api/runs/{run_id}/fs/observations?limit=5&offset=1000")["items"] == []


def test_a_late_lower_sequence_row_does_not_move_a_frozen_page_over_http(api):
    records = reportfx.build_records()
    run_id = seed(api, records[:20], state="running", start=100)
    first = ok(api, f"/api/runs/{run_id}/fs/observations?limit=500")
    conn = api.connect()
    try:
        reportfx.load(conn, records[20:30], run_id, start=5)                                # late rows with LOWER sequence numbers
    finally:
        conn.close()
    frozen = ok(api, f"/api/runs/{run_id}/fs/observations?limit=500&frontier={first['frontier']}")
    assert [i["seq"] for i in frozen["items"]] == [i["seq"] for i in first["items"]] == list(range(100, 120)) and frozen["total"] == 20
    live = ok(api, f"/api/runs/{run_id}/fs/observations?limit=500")
    assert live["total"] == 30 and [i["seq"] for i in live["items"]] == list(range(5, 15)) + list(range(100, 120))
    assert ok(api, f"/api/runs/{run_id}/fs/summary?frontier={first['frontier']}")["totals"]["records"] == 20


def test_the_unique_certificate_view_matches_the_oracle(seeded):
    api, run_id, records = seeded
    body = ok(api, f"/api/runs/{run_id}/fs/certificates?limit=500")
    expected = reportfx.unique(records)
    assert body["total"] == len(expected) == len(body["items"])
    for item, row in zip(body["items"], expected):
        assert item == {"sha256": row["sha256"], "subject": row["subject"], "issuer": row["issuer"], "not_before": row["not_before"],
                        "not_after": row["not_after"], "key_algorithm": row["key_algorithm"], "key_size": row["key_size"],
                        "key_curve": row["key_curve"], "signature_algorithm": row["signature_algorithm"],
                        "sightings": row["sightings"], "paths": row["paths"]}


@pytest.mark.parametrize("sort", ["sha256", "subject", "issuer", "key_algorithm", "key_size", "signature_algorithm", "not_after",
                                  "sightings", "paths"])
@pytest.mark.parametrize("direction", ["asc", "desc"])
def test_every_published_unique_sort_matches_the_oracle(seeded, sort, direction):
    api, run_id, records = seeded
    body = ok(api, f"/api/runs/{run_id}/fs/certificates?limit=500&sort={sort}&direction={direction}")
    assert [i["sha256"] for i in body["items"]] == [r["sha256"] for r in reportfx.unique(records, sort=sort, direction=direction)]


@pytest.mark.parametrize("query,filters", [("key_algorithm=EC", dict(key_algorithm="EC")), ("key_size=2048", dict(key_size=2048)),
                                           ("signature_algorithm=ed25519", dict(signature_algorithm="ed25519")),
                                           ("issuer=CN%3Dbeta%20CA", dict(issuer="CN=beta CA")), ("q=backup", dict(q="backup")),
                                           ("fingerprint=0000", dict(fingerprint="0000"))])
def test_unique_filters_over_http(seeded, query, filters):
    api, run_id, records = seeded
    body = ok(api, f"/api/runs/{run_id}/fs/certificates?limit=500&{query}")
    assert [i["sha256"] for i in body["items"]] == [r["sha256"] for r in reportfx.unique(records, **filters)]


# =========================================================================== summary, dashboard, statistics
def test_the_summary_matches_the_oracle(seeded):
    api, run_id, records = seeded
    body = ok(api, f"/api/runs/{run_id}/fs/summary")
    oracle = reportfx.summary_oracle(records, START)
    for block in ("totals", "parse_status", "formats", "validity", "expiry_buckets", "algorithms", "signature_algorithms", "issuers"):
        assert body[block] == oracle[block], block
    assert body["locations"]["directories"] == oracle["locations"]["directories"]
    assert body["as_of"] == "2026-03-01T12:00:00.000Z" and body["run"]["final"] is True and body["run"]["status"] in ("completed", "partial")
    assert body["expiring_days"] == {"value": 30, "source": "default"}


def test_top_changes_the_ranked_lists_and_nothing_else(seeded):
    api, run_id, records = seeded
    wide = ok(api, f"/api/runs/{run_id}/fs/summary?top=100")
    narrow = ok(api, f"/api/runs/{run_id}/fs/summary?top=2")
    assert len(narrow["issuers"]["top"]) == 2 and narrow["issuers"]["limit"] == 2 and narrow["issuers"]["other"]["groups"] == 2
    assert narrow["totals"] == wide["totals"]
    assert narrow["issuers"]["top"] == wide["issuers"]["top"][:2]


def test_a_summary_frontier_freezes_the_observations(seeded):
    api, run_id, records = seeded
    assert ok(api, f"/api/runs/{run_id}/fs/summary?frontier=3")["totals"]["records"] == 3
    assert ok(api, f"/api/runs/{run_id}/fs/summary?frontier=0")["totals"]["records"] == 0


def test_the_summary_uses_the_injected_clock(seeded):
    api, run_id, records = seeded
    api.clock.advance(60 * 60 * 24 * 400)
    body = ok(api, f"/api/runs/{run_id}/fs/summary")
    at_scan_time = reportfx.summary_oracle(records, START)["validity"]["now"]["unique"]["expired"]
    assert body["validity"]["now"]["unique"]["expired"] > at_scan_time          # more have expired by the later clock
    assert body["as_of"] > "2027-03-01"
    oracle = reportfx.summary_oracle(records, api.clock())
    assert body["validity"] == oracle["validity"] and body["expiry_buckets"] == oracle["expiry_buckets"]


def test_the_dashboard_summary_is_the_summary_of_the_latest_finished_filesystem_run(api):
    older = seed(api, reportfx.build_records()[:10])
    newer = seed(api, reportfx.build_records()[:20])
    running = seed(api, reportfx.build_records()[:5], state="running")
    body = ok(api, "/api/dashboard")
    assert body["latest_run"]["run_id"] == running and body["latest_run"]["status"] == "running"
    assert body["latest_terminal_fs_run"]["run_id"] == newer
    assert body["summary"] == ok(api, f"/api/runs/{newer}/fs/summary")
    assert body["runs_by_status"]["running"] == 1 and sum(body["runs_by_status"].values()) == 3
    assert [r["run_id"] for r in body["recent_runs"]] == [running, newer, older]
    assert set(body) == {"latest_run", "latest_terminal_fs_run", "summary", "runs_by_status", "recent_runs"}


def test_the_dashboard_of_an_empty_database(api):
    assert ok(api, "/api/dashboard") == {"latest_run": None, "latest_terminal_fs_run": None, "summary": None,
                                         "runs_by_status": {"queued": 0, "running": 0, "completed": 0, "partial": 0, "failed": 0},
                                         "recent_runs": []}


def test_dashboard_top_is_passed_to_the_summary(api):
    seed(api)
    assert ok(api, "/api/dashboard?top=1")["summary"]["issuers"]["limit"] == 1
    assert ok(api, "/api/dashboard")["summary"]["issuers"]["limit"] == 20


def test_run_statistics_shape_counts_and_filters(api):
    first = seed(api, reportfx.build_records()[:8])
    tls = api.create("tls")["run_id"]
    second = seed(api, reportfx.build_records()[:12], state="failed")
    body = ok(api, "/api/runs/stats")
    assert set(body) == {"by_type_status", "series"}
    assert body["by_type_status"] == [{"type": "filesystem", "status": "completed", "count": 1},
                                      {"type": "filesystem", "status": "failed", "count": 1},
                                      {"type": "tls", "status": "queued", "count": 1}]
    assert [r["run_id"] for r in body["series"]] == [first, tls, second]
    assert set(body["series"][0]) == {"run_id", "run_number", "type", "status", "started_at", "duration_ms", "record_count", "finding_count"}
    assert body["series"][0]["record_count"] == 8
    assert [r["run_id"] for r in ok(api, "/api/runs/stats?type=tls")["series"]] == [tls]
    assert [r["run_id"] for r in ok(api, "/api/runs/stats?limit=1")["series"]] == [second]
    assert ok(api, "/api/runs/stats?since=2999-01-01T00:00:00Z")["series"] == []
    assert len(ok(api, "/api/runs/stats?since=2026-03-01T12:00:00Z")["series"]) == 3


def test_stats_is_not_mistaken_for_a_run_id(api):
    run = api.create()
    assert "series" in ok(api, "/api/runs/stats")
    assert api.client.get(f"/api/runs/{run['run_id']}").json()["run"]["run_id"] == run["run_id"]


# =========================================================================== issues
def test_issues_over_http_are_paged_ordered_and_without_internal_ids(api):
    records = reportfx.build_records()
    run_id = seed(api, records, errors=[dir_error(r"C:\certs\private", "listdir"), dir_error(r"C:\gone", "root")])
    full = ok(api, f"/api/runs/{run_id}/issues")
    assert full["total"] == 2 and full["limit"] == 100 and full["offset"] == 0
    assert [(i["source"], i["kind"], i["path"]) for i in full["items"]] == [("agent", "listdir", r"C:\certs\private"), ("agent", "root", r"C:\gone")]
    assert all(set(i) == {"source", "kind", "code", "path", "seq"} for i in full["items"])
    one = ok(api, f"/api/runs/{run_id}/issues?limit=1&offset=1")
    assert one["items"] == full["items"][1:] and one["total"] == 2
    assert ok(api, f"/api/runs/{run_id}/issues?offset=5")["items"] == []


# =========================================================================== certificate detail
def test_certificate_detail_over_http(api):
    records = reportfx.build_records()
    first, second = seed(api, records[:14]), seed(api, records[:3])
    body = ok(api, f"/api/certificates/{sha(1)}")
    assert body["sha256"] == sha(1) and body["runs_total"] == 2 and body["runs_truncated"] is False
    assert [r["run_id"] for r in body["runs"]] == [second, first]                          # newest run first
    assert body["sightings_total"] == sum(r["sightings"] for r in body["runs"])
    newest = body["runs"][0]
    assert newest["paths"] == [r"C:\certs\site1.pem"] and newest["paths_count"] == 1 and newest["paths_truncated"] is False
    assert set(body) == {"sha256", "serial_hex", "subject", "issuer", "san", "key_algorithm", "key_size", "key_curve",
                         "signature_algorithm", "not_before", "not_after", "is_ca", "sightings_total", "runs_total", "runs_truncated", "runs"}
    assert body["san"] == [{"type": "DNS", "value": "host1.example.com"}] and body["serial_hex"] == "1"


def test_unknown_and_malformed_fingerprints(api):
    seed(api)
    unknown = get(api, f"/api/certificates/{sha(999)}")
    assert unknown.status_code == 404 and error_of(unknown)["code"] == "certificate_not_found"
    for bad in ("xyz", "A" * 64, "a" * 63, "a" * 65, "a" * 63 + "G", "0" * 63 + "%0A", "%D9%A1" * 64):
        response = get(api, f"/api/certificates/{bad}")
        assert response.status_code == 422 and error_of(response)["code"] == "validation_failed", bad


# =========================================================================== run state and type matrix
@pytest.mark.parametrize("state,status,final", [("running", "running", False), ("completed", "completed", True),
                                                ("partial", "partial", True), ("failed", "failed", True)])
def test_every_run_state_is_reportable(api, state, status, final):
    records = reportfx.build_records()[:10]
    run_id = seed(api, records, state=state)
    body = ok(api, f"/api/runs/{run_id}/fs/summary")
    assert body["run"]["status"] == status and body["run"]["final"] is final and body["totals"]["records"] == 10
    assert ok(api, f"/api/runs/{run_id}/fs/observations")["total"] == 10
    assert ok(api, f"/api/runs/{run_id}/fs/certificates")["total"] == len(reportfx.unique(records))
    assert ok(api, f"/api/runs/{run_id}/issues")["total"] == (1 if state == "partial" else 0)


def test_a_queued_run_gives_an_empty_report(api):
    run_id = api.create()["run_id"]
    body = ok(api, f"/api/runs/{run_id}/fs/summary")
    assert body["run"]["status"] == "queued" and body["run"]["final"] is False
    assert body["totals"]["records"] == 0 and body["frontier"] == 0
    assert ok(api, f"/api/runs/{run_id}/fs/observations") == {"items": [], "total": 0, "limit": 100, "offset": 0, "frontier": 0}
    assert ok(api, f"/api/runs/{run_id}/fs/certificates")["items"] == []
    assert ok(api, f"/api/runs/{run_id}/issues") == {"items": [], "total": 0, "limit": 100, "offset": 0}


@pytest.mark.parametrize("tail", RUN_SCOPED)
def test_a_tls_run_is_refused_with_409(api, tail):
    tls = api.create("tls")["run_id"]
    response = get(api, f"/api/runs/{tls}/{tail}")
    assert response.status_code == 409
    assert error_of(response) == {"code": "wrong_run_type", "message": "This report is not available for this type of run.",
                                  "details": {"required_type": "filesystem"}}


@pytest.mark.parametrize("tail", RUN_SCOPED)
def test_an_unknown_run_is_404(api, tail):
    response = get(api, f"/api/runs/{'0' * 32}/{tail}")
    assert response.status_code == 404 and error_of(response)["code"] == "run_not_found"


# =========================================================================== guards, methods, headers
@pytest.mark.parametrize("host", ["evil.example", "127.0.0.1.evil.example", "10.0.0.5", ""])
def test_every_report_route_refuses_foreign_hosts(api, host):
    run_id = seed(api, reportfx.build_records()[:3])
    for url in all_report_urls(run_id):
        response = api.client.get(url, headers={"host": host})
        assert response.status_code == 403 and error_of(response)["code"] == "host_not_allowed", url


@pytest.mark.parametrize("origin", ["http://evil.example", "null", "http://127.0.0.1.evil.example"])
def test_every_report_route_refuses_foreign_origins(api, origin):
    run_id = seed(api, reportfx.build_records()[:3])
    for url in all_report_urls(run_id):
        response = api.client.get(url, headers={"origin": origin})
        assert response.status_code == 403 and error_of(response)["code"] == "origin_not_allowed", url


def test_loopback_origins_and_hosts_are_served(api):
    run_id = seed(api, reportfx.build_records()[:3])
    for url in [*GLOBAL_URLS, *run_scoped_urls(run_id)]:
        assert get(api, url, headers={"origin": "http://localhost:5173", "host": "localhost:8000"}).status_code == 200


def test_every_response_of_every_report_route_is_no_store(api):
    run_id = seed(api, reportfx.build_records()[:5])
    tls = api.create("tls")["run_id"]
    urls = [*all_report_urls(run_id), f"/api/runs/{tls}/fs/summary", f"/api/runs/{'1' * 32}/issues", "/api/meta?x=1",
            f"/api/runs/{run_id}/fs/observations?limit=0", f"/api/certificates/{sha(77)}"]
    statuses = {get(api, url).status_code for url in urls}
    assert {200, 404, 409, 422} <= statuses


@pytest.mark.parametrize("url", ["/api/meta", "/api/dashboard", "/api/runs/stats", "/api/certificates/" + "a" * 64])
def test_report_routes_accept_only_get(api, url):
    for method in ("post", "put", "delete", "patch"):
        response = getattr(api.client, method)(url)
        assert response.status_code == 405 and error_of(response)["code"] == "method_not_allowed"


# =========================================================================== reads change nothing
def test_reports_never_change_the_database_nor_expire_a_stale_run(api):
    run_id = seed(api, reportfx.build_records(), state="running")
    api.clock.advance(3600)                                                                # far past every lease and queue timeout
    before = dump(api)
    for url in [*all_report_urls(run_id), f"/api/runs/{run_id}/fs/observations?q=host&sort=path", f"/api/runs/{run_id}/issues?limit=1"]:
        get(api, url)
    assert dump(api) == before
    conn = api.connect()
    try:
        assert conn.execute("SELECT status FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0] == "running"
    finally:
        conn.close()


def test_a_report_works_while_the_agent_is_writing(api):
    """A report taken between two batches of a running scan is internally consistent (it adds up) and the next one grows."""
    records = reportfx.build_records()
    run = api.create()
    agent = api.agent()
    agent.claim(run["run_id"])
    agent.upload_records(records[:20])
    first = ok(api, f"/api/runs/{run['run_id']}/fs/summary")
    agent.upload_records(records[20:], start=20)
    second = ok(api, f"/api/runs/{run['run_id']}/fs/summary")
    assert first["run"]["final"] is False and first["totals"]["records"] == 20 and second["totals"]["records"] == len(records)
    assert first["frontier"] < second["frontier"]
    assert first["totals"] == reportfx.summary_oracle(records[:20], START)["totals"]


# =========================================================================== end to end: fake agent -> report
def test_a_fake_agent_run_is_reported_end_to_end(api):
    records = reportfx.build_records()
    run = api.create()
    agent = api.agent()
    assert agent.claim(run["run_id"]).status_code == 200
    assert all(r.status_code == 200 for r in agent.upload_records(records))
    finished = agent.finish(summary=summary(len(records), roots=((reportfx.ROOT_C, "scanned"), (reportfx.ROOT_D, "scanned"))))
    assert finished.status_code == 200
    body = ok(api, f"/api/runs/{run['run_id']}/fs/summary")
    oracle = reportfx.summary_oracle(records, START)
    assert body["totals"] == oracle["totals"] and body["run"]["final"] is True
    run_row = api.get(run["run_id"])
    assert (body["totals"]["records"], body["totals"]["sightings"]) == (run_row["record_count"], run_row["finding_count"])
    dash = ok(api, "/api/dashboard")
    assert dash["summary"] == body and dash["latest_terminal_fs_run"]["run_id"] == run["run_id"]
    assert agent.token not in api.client.get(f"/api/runs/{run['run_id']}/fs/summary").text


# =========================================================================== privacy
def test_query_strings_are_never_logged(api, caplog):
    caplog.set_level(logging.DEBUG)
    run_id = seed(api, reportfx.build_records()[:5])
    for url in (f"/api/runs/{run_id}/fs/observations?q=SECRETNEEDLE", f"/api/runs/{run_id}/fs/observations?limit=SECRETVALUE",
                f"/api/runs/{run_id}/fs/observations?SECRETKEY=1", f"/api/runs/{run_id}/fs/observations?issuer=SECRETISSUER"):
        response = get(api, url)
        for secret in ("SECRETNEEDLE", "SECRETVALUE", "SECRETKEY", "SECRETISSUER"):
            assert secret not in response.text
    ours = " ".join(r.getMessage() for r in caplog.records if r.name.startswith("backend"))      # (the test client logs its own URLs)
    assert not any(s in ours for s in ("SECRETNEEDLE", "SECRETVALUE", "SECRETKEY", "SECRETISSUER"))


# =========================================================================== translation stays inside the report routes
def test_a_locked_database_is_still_a_503_busy_on_the_other_routes(api, monkeypatch):
    """The application-wide SQLite handler shares its mapping with the report routes; it must keep answering as before."""
    import sqlite3
    from backend import service

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(service, "list_runs", locked)
    response = api.client.get("/api/runs")
    assert response.status_code == 503 and error_of(response)["code"] == "busy" and response.headers["retry-after"] == "1"
    monkeypatch.setattr(service, "list_runs", lambda *a, **k: (_ for _ in ()).throw(sqlite3.DatabaseError("SECRET")))
    response = api.client.get("/api/runs")
    assert response.status_code == 500 and error_of(response)["code"] == "internal_error" and "SECRET" not in response.text



def test_the_error_translations_are_route_local_not_application_wide(api):
    from backend import db
    from backend.reports import InvalidQuery
    registered = api.app.exception_handlers
    assert runs.WrongRunType not in registered and InvalidQuery not in registered and db.QueryTimeout not in registered


def test_the_write_paths_still_answer_as_before(api):
    run = api.create("tls")
    agent = api.agent()
    claimed = agent.claim(run["run_id"])
    assert claimed.status_code == 200 and claimed.json()["run"]["status"] == "running"       # a TLS run is claimable since M3; the report errors do not touch this
    assert api.client.get(f"/api/runs/{run['run_id']}").status_code == 200
