"""The published shape of every report response: exact key sets (an allow-list), explicit exclusions, and no secret or raw
material anywhere. The response models are the allow-list; these tests pin it so a field cannot appear by accident."""
import json

import pytest

import reportfx
from backend import report_models as models
from backend.safety import is_raw_material_name
from ingestfx import dir_error, sha
from reportapifx import seed

SIGHTING_KEYS = {"seq", "entry_ordinal", "path", "filename", "scan_root", "format", "discovered_at", "sha256", "chain_index", "chain_total",
                 "chain_role", "parse_status", "detail", "access_error", "evidence_confidence", "validity_status", "days_to_expiry",
                 "duplicate_kind", "serial_hex", "subject", "issuer", "san", "key_algorithm", "key_size", "key_curve",
                 "signature_algorithm", "not_before", "not_after", "warnings", "owning_process"}
UNIQUE_KEYS = {"sha256", "subject", "issuer", "not_before", "not_after", "key_algorithm", "key_size", "key_curve", "signature_algorithm",
               "sightings", "paths"}
RUN_BRIEF_KEYS = {"run_id", "run_number", "type", "status", "started_at", "duration_ms", "record_count", "finding_count"}
CERTIFICATE_KEYS = {"sha256", "serial_hex", "subject", "issuer", "san", "key_algorithm", "key_size", "key_curve", "signature_algorithm",
                    "not_before", "not_after", "is_ca", "sightings_total", "runs_total", "runs_truncated", "runs"}
CERTIFICATE_RUN_KEYS = {"run_id", "run_number", "sightings", "paths_count", "paths", "paths_truncated"}
SUMMARY_KEYS = {"run", "as_of", "frontier", "frontier_scope", "expiring_days", "totals", "parse_status", "formats", "validity",
                "expiry_buckets", "algorithms", "signature_algorithms", "issuers", "locations", "issues"}

EXCLUDED_EVERYWHERE = {"id", "run_id_internal", "lease_token", "lease_token_hash", "token", "token_hash", "private_key", "key_material",
                       "der", "pem", "raw", "password", "owning_process_json", "warnings_json", "san_json", "config_json", "agent_summary_json",
                       "first_seen_run", "first_seen_at", "last_seen_run", "last_seen_at", "first_seq", "first_path", "uniq"}
EXCLUDED_FROM_OBSERVATIONS = {"extension_mismatch", "not_yet_valid", "is_ca"}
FORMAT_NAMES = {"pem", "der", "pkcs12", "unknown"}                      # the values of a closed list, used as keys of `formats`


@pytest.fixture
def world(api):
    records = reportfx.build_records()
    run_id = seed(api, records, errors=[dir_error()])
    agent = api.agent()
    other = api.create()["run_id"]
    agent.claim(other)                                                  # a live lease token exists while the reports are read
    return api, run_id, agent.token


def all_json(api, run_id):
    urls = ["/api/meta", "/api/dashboard", "/api/runs/stats", f"/api/runs/{run_id}/fs/summary", f"/api/runs/{run_id}/fs/observations?limit=500",
            f"/api/runs/{run_id}/fs/certificates?limit=500", f"/api/runs/{run_id}/issues", f"/api/certificates/{sha(1)}"]
    return {url: api.client.get(url).json() for url in urls}


def keys_of(value, found=None):
    found = set() if found is None else found
    if isinstance(value, dict):
        for key, inner in value.items():
            found.add(key)
            keys_of(inner, found)
    elif isinstance(value, list):
        for inner in value:
            keys_of(inner, found)
    return found


# =========================================================================== exact shapes
def test_observation_items_have_exactly_the_published_fields(world):
    api, run_id, _ = world
    items = api.client.get(f"/api/runs/{run_id}/fs/observations?limit=500").json()["items"]
    assert items and all(set(item) == SIGHTING_KEYS for item in items)
    assert all(item["owning_process"] is None for item in items)
    assert not (keys_of(items) & EXCLUDED_FROM_OBSERVATIONS)


def test_unique_items_have_exactly_the_published_fields(world):
    api, run_id, _ = world
    items = api.client.get(f"/api/runs/{run_id}/fs/certificates?limit=500").json()["items"]
    assert items and all(set(item) == UNIQUE_KEYS for item in items)


def test_envelopes(world):
    api, run_id, _ = world
    for tail in ("fs/observations", "fs/certificates"):
        assert set(api.client.get(f"/api/runs/{run_id}/{tail}").json()) == {"items", "total", "limit", "offset", "frontier"}
    assert set(api.client.get(f"/api/runs/{run_id}/issues").json()) == {"items", "total", "limit", "offset"}
    assert set(api.client.get("/api/runs/stats").json()) == {"by_type_status", "series"}
    assert set(api.client.get("/api/dashboard").json()) == {"latest_run", "latest_terminal_fs_run", "summary", "runs_by_status", "recent_runs"}
    assert set(api.client.get("/api/meta").json()) == {"data_origin", "schema_version", "server_time"}


def test_run_entries_use_exactly_the_eight_statistics_fields(world):
    api, run_id, _ = world
    stats, dashboard = api.client.get("/api/runs/stats").json(), api.client.get("/api/dashboard").json()
    assert all(set(r) == RUN_BRIEF_KEYS for r in stats["series"])
    assert set(dashboard["latest_run"]) == set(dashboard["latest_terminal_fs_run"]) == RUN_BRIEF_KEYS
    assert all(set(r) == RUN_BRIEF_KEYS for r in dashboard["recent_runs"])
    assert all(set(g) == {"type", "status", "count"} for g in stats["by_type_status"])


def test_the_summary_has_exactly_the_published_blocks_and_as_of_only_here(world):
    api, run_id, _ = world
    body = api.client.get(f"/api/runs/{run_id}/fs/summary").json()
    assert set(body) == SUMMARY_KEYS and "as_of" in body
    assert set(body["run"]) == {"run_id", "run_number", "type", "status", "final", "started_at", "finished_at"}
    assert set(body["issues"]) == {"errors", "rejected", "seq_conflicts"}
    assert set(body["issues"]["errors"]) == {"total", "file_errors", "directory_errors", "unresolved_read_errors"}
    assert set(body["frontier_scope"]) == {"frozen", "live"} and set(body["expiring_days"]) == {"value", "source"}
    others = [api.client.get(u).json() for u in (f"/api/runs/{run_id}/fs/observations", f"/api/runs/{run_id}/fs/certificates",
                                                 f"/api/runs/{run_id}/issues", "/api/runs/stats", "/api/meta", f"/api/certificates/{sha(1)}")]
    assert all("as_of" not in o for o in others)
    assert "as_of" not in api.client.get("/api/dashboard").json()


def test_the_ranked_lists_publish_only_their_own_fields(world):
    api, run_id, _ = world
    body = api.client.get(f"/api/runs/{run_id}/fs/summary?top=2").json()
    for name, item_keys, other_keys in (("algorithms", {"key_algorithm", "key_size", "key_curve", "unique", "sightings"}, {"groups", "unique", "sightings"}),
                                        ("signature_algorithms", {"signature_algorithm", "unique", "sightings"}, {"groups", "unique", "sightings"}),
                                        ("issuers", {"issuer", "unique", "sightings"}, {"groups", "unique", "sightings"})):
        ranked = body[name]
        assert set(ranked) == {"top", "other", "total_groups", "limit"} and all(set(i) == item_keys for i in ranked["top"])
        assert set(ranked["other"]) == other_keys
    roots, dirs = body["locations"]["scan_roots"], body["locations"]["directories"]
    assert all(set(i) == {"scan_root", "observations", "sightings", "unique"} for i in roots["top"])
    assert all(set(i) == {"directory", "sightings", "unique"} for i in dirs["top"]) and set(dirs["other"]) == {"groups", "sightings"}


def test_certificate_detail_has_exactly_the_published_fields(world):
    api, run_id, _ = world
    body = api.client.get(f"/api/certificates/{sha(1)}").json()
    assert set(body) == CERTIFICATE_KEYS and all(set(r) == CERTIFICATE_RUN_KEYS for r in body["runs"])
    assert all(set(s) == {"type", "value"} for s in body["san"])
    assert not (keys_of(body) & {"first_seen_run", "first_seen_at", "last_seen_run", "last_seen_at", "extension_mismatch", "not_yet_valid"})


def test_issue_items_have_no_internal_id(world):
    api, run_id, _ = world
    items = api.client.get(f"/api/runs/{run_id}/issues").json()["items"]
    assert items and all(set(i) == {"source", "kind", "code", "path", "seq"} for i in items)


def test_the_models_are_the_allow_list(world):
    """Every model field is published; nothing outside the models can reach a response."""
    published = (set(models.Sighting.model_fields) | set(models.UniqueCertificate.model_fields) | set(models.Issue.model_fields)
                 | set(models.CertificateDetail.model_fields) | set(models.CertificateRun.model_fields))
    assert not (published & EXCLUDED_EVERYWHERE)
    assert not (set(models.Sighting.model_fields) & EXCLUDED_FROM_OBSERVATIONS)
    assert set(models.Sighting.model_fields) == SIGHTING_KEYS and set(models.UniqueCertificate.model_fields) == UNIQUE_KEYS
    assert set(models.RunBrief.model_fields) == RUN_BRIEF_KEYS and set(models.CertificateDetail.model_fields) == CERTIFICATE_KEYS


# =========================================================================== no secrets, no raw material
def test_no_response_contains_secret_or_raw_material_keys_or_text(world):
    api, run_id, token = world
    responses = all_json(api, run_id)
    for url, body in responses.items():
        names = keys_of(body)
        assert not (names & (EXCLUDED_EVERYWHERE - FORMAT_NAMES)), (url, names & (EXCLUDED_EVERYWHERE - FORMAT_NAMES))
        assert [n for n in names if is_raw_material_name(n) and n not in FORMAT_NAMES] == [], url
        text = json.dumps(body)
        for forbidden in ("PRIVATE KEY", "BEGIN CERTIFICATE", "BEGIN ", token, "lease"):
            assert forbidden not in text, (url, forbidden)


def test_every_collection_is_bounded_by_its_documented_cap(world):
    api, run_id, _ = world
    assert api.client.get(f"/api/runs/{run_id}/fs/observations?limit=500").status_code == 200
    assert api.client.get(f"/api/runs/{run_id}/fs/observations?limit=501").status_code == 422
    body = api.client.get(f"/api/runs/{run_id}/fs/summary?top=100").json()
    assert len(body["issuers"]["top"]) <= 100 and len(body["locations"]["scan_roots"]["top"]) <= 100
    assert api.client.get(f"/api/runs/{run_id}/fs/summary?top=101").status_code == 422
    assert len(api.client.get("/api/dashboard").json()["recent_runs"]) <= 10
    assert len(api.client.get("/api/runs/stats").json()["series"]) <= 200


def test_responses_are_deterministic(world):
    api, run_id, _ = world
    first, second = all_json(api, run_id), all_json(api, run_id)
    assert first == second


# =========================================================================== the models are attached to the routes
def app_routes_in_order(app):
    """Every APIRoute of the application in matching order. Newer FastAPI keeps an included router as one wrapper object
    (`original_router`), older versions copy its routes into the application: both are handled."""
    from fastapi.routing import APIRoute
    found = []
    for route in app.routes:
        inner = getattr(route, "original_router", None)
        found += [r for r in (inner.routes if inner is not None else [route]) if isinstance(r, APIRoute)]
    return found


def test_every_report_route_declares_exactly_its_response_model(api):
    """The response models are the allow-list, so each route must keep ITS model: losing it, or being given another, fails here."""
    expected = {
        ("GET", "/api/meta"): models.Meta,
        ("GET", "/api/dashboard"): models.Dashboard,
        ("GET", "/api/runs/stats"): models.RunStatistics,
        ("GET", "/api/runs/{run_id}/fs/summary"): models.Summary,
        ("GET", "/api/runs/{run_id}/fs/observations"): models.SightingPage,
        ("GET", "/api/runs/{run_id}/fs/certificates"): models.UniqueCertificatePage,
        ("GET", "/api/runs/{run_id}/issues"): models.IssuePage,
        ("GET", "/api/certificates/{sha256}"): models.CertificateDetail,
    }
    declared = {(method, route.path): route.response_model
                for route in app_routes_in_order(api.app) if route.endpoint.__module__ == "backend.report_routes"
                for method in sorted(route.methods)}
    assert set(declared) == set(expected), "a report route was added, removed or given other methods"
    for key, model in expected.items():
        assert declared[key] is model, (key, declared[key])


def test_the_stats_route_is_registered_before_the_run_detail_route(api):
    paths = [route.path for route in app_routes_in_order(api.app) if "GET" in route.methods]
    assert paths.index("/api/runs/stats") < paths.index("/api/runs/{run_id}")
