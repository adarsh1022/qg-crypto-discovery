"""The TLS report endpoints over HTTP: published shapes, errors, validation, run isolation, read-only behaviour, no secrets."""
import json
import random

import pytest

from apifx import make_api
from reportapifx import dump
from tlsingestfx import build_tls_records, failed_record, peer, sha, tls_record
from tlsingestfx import seed_tls_run

SUMMARY_KEYS = {"run", "as_of", "frontier", "frontier_scope", "totals", "outcomes", "tls_versions", "cipher_suites", "process_attribution",
                "certificate_validity", "issues", "scan"}
TOTALS_KEYS = {"probe_attempts", "handshakes_completed", "not_completed", "endpoints", "certificates_presented", "leaf_certificates"}
OBSERVATION_KEYS = {"seq", "observed_at", "direction", "transport", "src_ip", "src_port", "dst_ip", "dst_port", "handshake_outcome", "sni",
                    "tls_version", "cipher_suite", "cert_visibility", "pid", "process_name", "exe_path", "process_attribution",
                    "event_count", "packet_count", "event_counts", "evidence_confidence", "warnings", "peer_certificates"}
PEER_KEYS = {"position", "sha256", "subject", "issuer", "not_before", "not_after", "key_algorithm", "key_size", "key_curve",
             "signature_algorithm", "is_ca"}
SCAN_KEYS = {"stop_reason", "enumeration", "listeners_found", "port_filtered", "policy_skipped", "targets_planned", "targets_probed",
             "targets_truncated"}
EXCLUDED = {"id", "internal_id", "local_ip", "local_port", "remote_ip", "remote_port", "last_event_at", "cipher_id", "lease_token",
            "lease_token_hash", "token", "private_key", "der", "pem", "raw", "agent_summary_json", "warnings_json", "event_counts_json",
            "config_json"}
TAILS = ("tls/summary", "tls/observations", "tls/issues")


def url(run_id, tail, query=""):
    return f"/api/runs/{run_id}/{tail}{query}"


def err(response):
    return response.json()["error"]


def get_ok(api, path):
    response = api.client.get(path)
    assert response.status_code == 200, (path, response.text)
    return response.json()


def all_keys(value, found=None):
    found = set() if found is None else found
    if isinstance(value, dict):
        found.update(value)
        for v in value.values():
            all_keys(v, found)
    elif isinstance(value, list):
        for v in value:
            all_keys(v, found)
    return found


@pytest.fixture
def world(api):
    return api, seed_tls_run(api)


# ------------------------------------------------------------------ published shapes
def test_the_summary_has_exactly_the_published_fields(world):
    api, run_id = world
    body = get_ok(api, url(run_id, "tls/summary"))
    assert set(body) == SUMMARY_KEYS and set(body["totals"]) == TOTALS_KEYS and set(body["scan"]) == SCAN_KEYS
    assert body["totals"] == {"probe_attempts": 10, "handshakes_completed": 6, "not_completed": 4, "endpoints": 10, "certificates_presented": 7, "leaf_certificates": 5}
    assert body["run"]["status"] == "completed" and body["run"]["final"] is True and body["run"]["type"] == "tls"
    assert set(body["certificate_validity"]) == {"expiring_days", "now"} and body["certificate_validity"]["expiring_days"] == {"value": 30, "source": "default"}
    assert set(body["issues"]) == {"errors", "rejected", "seq_conflicts"} and set(body["issues"]["errors"]) == {"total", "enumerate", "probe"}
    assert set(body["cipher_suites"]) == {"top", "other", "total_groups", "limit"}


def test_an_observation_page_has_exactly_the_published_fields(world):
    api, run_id = world
    page = get_ok(api, url(run_id, "tls/observations"))
    assert set(page) == {"items", "total", "limit", "offset", "frontier"} and page["total"] == 10 and len(page["items"]) == 10
    for item in page["items"]:
        assert set(item) == OBSERVATION_KEYS and all(set(p) == PEER_KEYS for p in item["peer_certificates"])
    first = page["items"][0]
    assert (first["direction"], first["event_count"], first["packet_count"], first["sni"]) == ("unknown", 1, 0, None)
    assert "active_probe" in first["warnings"] and "packet_counts_unavailable" in first["warnings"]
    assert [p["position"] for p in first["peer_certificates"]] == [0, 1, 2]


def test_an_issue_page_has_the_shared_shape(api):
    run_id = seed_tls_run(api, state="partial")
    page = get_ok(api, url(run_id, "tls/issues"))
    assert set(page) == {"items", "total", "limit", "offset"} and page["total"] == 1
    assert page["items"] == [{"source": "agent", "kind": "probe", "code": "target_not_local", "path": None, "seq": None}]


def test_nothing_internal_or_secret_is_ever_published(world):
    api, run_id = world
    bodies = [get_ok(api, url(run_id, t, "?limit=500" if t == "tls/observations" else "")) for t in TAILS]
    assert not (all_keys(bodies) & EXCLUDED)
    text = json.dumps(bodies)
    assert "BEGIN" not in text and "PRIVATE" not in text and "MII" not in text


def test_the_response_models_are_an_allow_list(world, monkeypatch):
    """Whatever the report layer returns, only the published fields leave the service."""
    from backend import tls_report_routes
    from backend.reports import Page
    api, run_id = world
    real = tls_report_routes.search_observations

    def leaky(conn, run, query):
        page = real(conn, run, query)
        items = [{**item, "internal_id": 99, "lease_token": "secret", "der": "MIIB", "local_ip": "10.0.0.1"} for item in page.items]
        return Page(items, page.total, page.limit, page.offset, page.frontier)

    monkeypatch.setattr(tls_report_routes, "search_observations", leaky)
    body = get_ok(api, url(run_id, "tls/observations"))
    assert not (all_keys(body) & {"internal_id", "lease_token", "der", "local_ip"}) and "MIIB" not in json.dumps(body)


def test_a_result_that_does_not_fit_its_model_is_a_safe_500(world, monkeypatch):
    from backend import tls_report_routes
    api, run_id = world
    monkeypatch.setattr(tls_report_routes, "tls_summary", lambda *a, **k: {"totals": "nonsense", "secret": "C:\\private"})
    response = api.client.get(url(run_id, "tls/summary"))
    assert response.status_code == 500 and err(response)["code"] == "internal_error"
    assert response.headers["cache-control"] == "no-store" and "private" not in response.text


# ------------------------------------------------------------------ headers and errors
def test_every_response_is_no_store_including_errors(world):
    api, run_id = world
    urls = [url(run_id, t) for t in TAILS] + [url("f" * 32, "tls/summary"), url(run_id, "tls/summary", "?x=1"), url(run_id, "tls/observations", "?limit=0")]
    for u in urls:
        assert api.client.get(u).headers["cache-control"] == "no-store", u


def test_an_unknown_run_is_404(api):
    for tail in TAILS:
        response = api.client.get(url("f" * 32, tail))
        assert response.status_code == 404 and err(response)["code"] == "run_not_found"


def test_a_filesystem_run_gets_409_naming_the_required_type(api):
    fs_run = api.create("filesystem", config={"roots": ["C:\\x"]})["run_id"]
    for tail in TAILS:
        response = api.client.get(url(fs_run, tail))
        assert response.status_code == 409 and err(response) == {
            "code": "wrong_run_type", "message": "This report is not available for this type of run.", "details": {"required_type": "tls"}}


def test_the_filesystem_reports_still_refuse_a_tls_run_as_before(world):
    api, run_id = world
    for tail in ("fs/summary", "fs/observations", "fs/certificates", "issues"):
        response = api.client.get(url(run_id, tail))
        assert response.status_code == 409 and err(response)["details"] == {"required_type": "filesystem"}, tail


def test_malformed_run_ids_are_not_found_not_errors(api):
    for bad in ("0", "g" * 32, "A" * 32, "x" * 200):
        assert api.client.get(f"/api/runs/{bad}/tls/summary").status_code == 404


def test_only_get_is_allowed(world):
    api, run_id = world
    for tail in TAILS:
        assert api.client.post(url(run_id, tail)).status_code == 405 and api.client.delete(url(run_id, tail)).status_code == 405


# ------------------------------------------------------------------ query validation
VALIDATION = [
    ("tls/observations", "outcome=bogus", [("outcome", "unknown_value")]), ("tls/observations", "tls_version=TLSv1.3", [("tls_version", "unknown_value")]),
    ("tls/observations", "process_attribution=guessed", [("process_attribution", "unknown_value")]),
    ("tls/observations", "dst_port=0", [("dst_port", "out_of_range")]), ("tls/observations", "dst_port=65536", [("dst_port", "out_of_range")]),
    ("tls/observations", "dst_port=abc", [("dst_port", "not_an_integer")]), ("tls/observations", "dst_port=-1", [("dst_port", "not_an_integer")]),
    ("tls/observations", "fingerprint=xyz", [("fingerprint", "not_a_hex_prefix_of_4_to_64_characters")]),
    ("tls/observations", "q=", [("q", "empty_value")]), ("tls/observations", "sort=path", [("sort", "unknown_value")]),
    ("tls/observations", "direction=up", [("direction", "unknown_value")]), ("tls/observations", "limit=0", [("limit", "out_of_range")]),
    ("tls/observations", "limit=501", [("limit", "out_of_range")]), ("tls/observations", "offset=-1", [("offset", "not_an_integer")]),
    ("tls/observations", "outcome=failed&outcome=alert", [("outcome", "repeated_parameter")]),
    ("tls/observations", "unknown=1", [("query", "unknown_parameter")]), ("tls/observations", "has_warnings=true", [("query", "unknown_parameter")]),
    ("tls/observations", "frontier=99999999999999999999", [("frontier", "out_of_range")]),
    ("tls/summary", "top=0", [("top", "out_of_range")]), ("tls/summary", "top=101", [("top", "out_of_range")]), ("tls/summary", "top=x", [("top", "not_an_integer")]),
    ("tls/summary", "limit=5", [("query", "unknown_parameter")]), ("tls/summary", "frontier=-5", [("frontier", "not_an_integer")]),
    ("tls/issues", "limit=0", [("limit", "out_of_range")]), ("tls/issues", "offset=-1", [("offset", "not_an_integer")]),
    ("tls/issues", "q=a", [("query", "unknown_parameter")]),
]


@pytest.mark.parametrize("tail,query,expected", VALIDATION)
def test_invalid_queries_are_422_with_fixed_field_names(world, tail, query, expected):
    api, run_id = world
    response = api.client.get(url(run_id, tail, "?" + query))
    assert response.status_code == 422 and err(response)["code"] == "validation_failed"
    assert [(p["field"], p["problem"]) for p in err(response)["details"]["problems"]] == expected
    value = query.split("=", 1)[-1]
    assert len(value) < 4 or value not in response.text                              # what was sent is not echoed back


def test_a_valid_query_with_every_parameter_works(world):
    api, run_id = world
    page = get_ok(api, url(run_id, "tls/observations", "?outcome=completed&tls_version=TLS1.3&process_attribution=attributed&dst_port=8443"
                           "&fingerprint=" + sha(1) + "&q=python&sort=dst_port&direction=desc&limit=5&offset=0&frontier=100"))
    assert page["total"] == 1 and page["items"][0]["seq"] == 0


# ------------------------------------------------------------------ run states
def test_a_queued_run_has_an_empty_report_and_no_scan_facts(api):
    run_id = seed_tls_run(api, state="queued")
    summary = get_ok(api, url(run_id, "tls/summary"))
    assert summary["run"]["status"] == "queued" and summary["run"]["final"] is False and summary["totals"]["probe_attempts"] == 0 and summary["scan"] is None
    assert get_ok(api, url(run_id, "tls/observations"))["total"] == 0 and get_ok(api, url(run_id, "tls/issues"))["total"] == 0


def test_a_running_run_reports_what_exists_so_far_and_pages_stay_stable(api):
    run_id = seed_tls_run(api, build_tls_records()[:4], state="running")
    summary = get_ok(api, url(run_id, "tls/summary"))
    assert summary["run"]["final"] is False and summary["scan"] is None and summary["totals"]["probe_attempts"] == 4 and summary["totals"]["handshakes_completed"] == 3
    page = get_ok(api, url(run_id, "tls/observations", "?limit=2"))
    assert page["total"] == 4 and page["frontier"] == summary["frontier"]


def test_a_partial_run_shows_its_errors_and_still_lists_what_was_found(api):
    run_id = seed_tls_run(api, state="partial")
    summary = get_ok(api, url(run_id, "tls/summary"))
    assert summary["run"]["status"] == "partial" and summary["issues"]["errors"] == {"total": 1, "enumerate": 0, "probe": 1}
    assert summary["totals"]["probe_attempts"] == 10 and api.get(run_id)["error_count"] == 1


def test_a_failed_run_with_no_records_is_not_an_empty_success(api):
    run_id = seed_tls_run(api, [], state="failed")
    summary = get_ok(api, url(run_id, "tls/summary"))
    assert summary["run"]["status"] == "failed" and summary["totals"]["probe_attempts"] == 0 and summary["scan"] is None
    assert api.get(run_id)["error_summary"] == "boom" and get_ok(api, url(run_id, "tls/observations"))["items"] == []


def test_a_failed_enumeration_is_visible_in_the_scan_facts_and_the_issues(api):
    run_id = seed_tls_run(api, [], state="enumeration_failed")
    summary = get_ok(api, url(run_id, "tls/summary"))
    assert summary["run"]["status"] == "failed" and summary["scan"]["enumeration"] == "failed" and summary["scan"]["stop_reason"] == "enumeration_failed"
    assert get_ok(api, url(run_id, "tls/issues"))["items"] == [{"source": "agent", "kind": "enumerate", "code": "table_unreadable", "path": None, "seq": None}]


def test_zero_eligible_listeners_is_a_completed_run_with_ok_enumeration(api):
    from tlsingestfx import tls_summary
    run_id = seed_tls_run(api, [], summary=tls_summary(0, listeners_found=5, policy_skipped=5, targets_planned=0, targets_probed=0))
    summary = get_ok(api, url(run_id, "tls/summary"))
    assert summary["run"]["status"] == "completed" and summary["scan"]["enumeration"] == "ok" and summary["scan"]["listeners_found"] == 5
    assert summary["scan"]["policy_skipped"] == 5 and summary["totals"]["probe_attempts"] == 0 and summary["issues"]["errors"]["total"] == 0


# ------------------------------------------------------------------ duplicates, certificates, isolation
def test_the_same_certificate_in_two_observations_is_two_rows_and_one_certificate(world):
    api, run_id = world
    page = get_ok(api, url(run_id, "tls/observations", f"?fingerprint={sha(1)}"))
    assert [i["seq"] for i in page["items"]] == [0, 2] and page["items"][0]["peer_certificates"] == page["items"][1]["peer_certificates"]
    assert get_ok(api, url(run_id, "tls/summary"))["totals"]["leaf_certificates"] == 5


def test_the_shared_certificate_detail_endpoint_keeps_describing_filesystem_sightings_only(world):
    api, run_id = world
    detail = get_ok(api, f"/api/certificates/{sha(1)}")
    assert detail["subject"] == "CN=cert1" and detail["sightings_total"] == 0 and detail["runs_total"] == 0 and detail["runs"] == []   # unchanged


def test_two_runs_are_isolated(api):
    a, b = seed_tls_run(api), seed_tls_run(api, [tls_record(1, port=7000)], state="completed")
    assert get_ok(api, url(a, "tls/summary"))["totals"]["probe_attempts"] == 10 and get_ok(api, url(b, "tls/summary"))["totals"]["probe_attempts"] == 1
    assert [i["dst_port"] for i in get_ok(api, url(b, "tls/observations"))["items"]] == [7000]
    assert get_ok(api, url(b, "tls/observations", "?dst_port=8443"))["total"] == 0


def test_filesystem_and_tls_runs_do_not_leak_into_each_others_reports(api):
    from backend import fs_ingest
    from ingestfx import at, ok_record, running_run, summary as fs_summary
    tls_run = seed_tls_run(api, [tls_record(2)])
    conn = api.connect()
    try:
        fs_run = running_run(conn)
        fs_ingest.ingest_fs_batch(conn, fs_run, fs_ingest.number_records([ok_record(n=1)]), now=at(2))
        fs_ingest.finalize_fs_run(conn, fs_run, now=at(10), summary=fs_summary(1))
    finally:
        conn.close()
    assert get_ok(api, url(tls_run, "tls/summary"))["totals"]["probe_attempts"] == 1
    assert get_ok(api, f"/api/runs/{fs_run}/fs/summary")["totals"]["records"] == 1


# ------------------------------------------------------------------ reading changes nothing
def test_reading_the_tls_reports_changes_nothing(api):
    ids = [seed_tls_run(api), seed_tls_run(api, state="partial"), seed_tls_run(api, state="queued"), seed_tls_run(api, [], state="enumeration_failed")]
    before = dump(api)
    for run_id in ids:
        for tail in TAILS:
            api.client.get(url(run_id, tail))
        api.client.get(url(run_id, "tls/observations", "?q=python&sort=process_name&limit=3"))
    assert dump(api) == before


# ------------------------------------------------------------------ the time budget
class Runaway:
    def __init__(self):
        self.now, self.running_away = 0.0, False

    def __call__(self):
        if self.running_away:
            self.now += 1000.0
        return self.now


def test_a_request_that_runs_out_of_time_is_the_agreed_503(tmp_path):
    clock = Runaway()
    api = make_api(tmp_path, budget_clock=clock)
    rng = random.Random(3)
    records = [tls_record(rng.randint(1, 40), port=2000 + i, src_port=40000 + i) for i in range(400)]
    run_id = seed_tls_run(api, records, state="running")
    clock.running_away = True
    for path in (url(run_id, "tls/summary"), url(run_id, "tls/observations", "?q=python&sort=process_name")):
        response = api.client.get(path)
        assert response.status_code == 503, (path, response.text)
        assert response.json() == {"error": {"code": "query_timeout", "message": "The request took too long and was stopped. Narrow the filters and try again.",
                                             "details": {"budget_seconds": 5.0}}}
        assert response.headers["retry-after"] == "1" and response.headers["cache-control"] == "no-store"
    clock.running_away = False
    assert api.client.get(url(run_id, "tls/summary")).status_code == 200                    # the service is fine afterwards


# ------------------------------------------------------------------ the local-only guards apply here too
def test_a_foreign_host_or_origin_is_refused(world):
    api, run_id = world
    assert api.client.get(url(run_id, "tls/summary"), headers={"host": "evil.example"}).status_code == 403
    assert api.client.get(url(run_id, "tls/summary"), headers={"origin": "http://evil.example"}).status_code == 403
    _ = (failed_record, peer)
