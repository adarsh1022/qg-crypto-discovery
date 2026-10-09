"""Strict query validation on every report endpoint: unknown and repeated parameters, empty values, non-ASCII numerals,
wrong types and out-of-range values are refused with 422 and a fixed problem code, and nothing the caller sent is echoed."""
import pytest

import reportfx
from reportapifx import seed

LONG_DIGITS = "9" * 20


def short(case):
    """Readable, short test ids (some queries are tens of thousands of characters long and would become file names)."""
    return str(case)[:40]


@pytest.fixture
def run_id(api):
    return seed(api, reportfx.build_records()[:12])


def problems_of(response):
    assert response.status_code == 422, (response.status_code, response.text)
    assert response.headers.get("cache-control") == "no-store"
    body = response.json()
    assert body["error"]["code"] == "validation_failed" and set(body["error"]) == {"code", "message", "details"}
    assert set(body["error"]["details"]) == {"problems"}
    return [(p["field"], p["problem"]) for p in body["error"]["details"]["problems"]]


# the parameters every list endpoint shares
PAGING = [
    ("limit=0", "limit", "out_of_range"), ("limit=501", "limit", "out_of_range"), ("limit=-1", "limit", "not_an_integer"),
    ("limit=abc", "limit", "not_an_integer"), ("limit=1.5", "limit", "not_an_integer"), ("limit=1e2", "limit", "not_an_integer"),
    ("limit=0x10", "limit", "not_an_integer"), ("limit=5_0", "limit", "not_an_integer"), ("limit=%2B5", "limit", "not_an_integer"),
    ("limit=%205", "limit", "not_an_integer"), ("limit=5%20", "limit", "not_an_integer"), ("limit=5%0A", "limit", "not_an_integer"),
    ("limit=%D9%A5", "limit", "not_an_integer"),                              # ARABIC-INDIC DIGIT FIVE
    ("limit=%EF%BC%95", "limit", "not_an_integer"),                          # FULLWIDTH DIGIT FIVE
    ("limit=%C2%B2", "limit", "not_an_integer"),                             # SUPERSCRIPT TWO
    ("limit=", "limit", "empty_value"), ("limit=1&limit=2", "limit", "repeated_parameter"), ("limit=5&limit=5", "limit", "repeated_parameter"),
    ("limit=" + LONG_DIGITS, "limit", "out_of_range"),
    ("offset=-1", "offset", "not_an_integer"), ("offset=10000001", "offset", "out_of_range"), ("offset=", "offset", "empty_value"),
    ("offset=" + LONG_DIGITS, "offset", "out_of_range"), ("offset=%D9%A5", "offset", "not_an_integer"),
    ("offset=1&offset=1", "offset", "repeated_parameter"),
    ("frontier=-1", "frontier", "not_an_integer"), ("frontier=4611686018427387905", "frontier", "out_of_range"),
    ("frontier=", "frontier", "empty_value"), ("frontier=%D9%A5", "frontier", "not_an_integer"), ("frontier=1&frontier=2", "frontier", "repeated_parameter"),
]
SORTING = [
    ("sort=bogus", "sort", "unknown_value"), ("sort=SEQ", "sort", "unknown_value"), ("sort=seq%3Bdrop", "sort", "unknown_value"),
    ("sort=", "sort", "empty_value"), ("sort=seq&sort=path", "sort", "repeated_parameter"),
    ("direction=up", "direction", "unknown_value"), ("direction=ASC", "direction", "unknown_value"), ("direction=", "direction", "empty_value"),
]
SEARCH = [
    ("q=", "q", "empty_value"), ("q=" + "x" * 201, "q", "too_long"), ("q=a&q=b", "q", "repeated_parameter"),
    ("fingerprint=abc", "fingerprint", "not_a_hex_prefix_of_4_to_64_characters"),
    ("fingerprint=" + "a" * 65, "fingerprint", "not_a_hex_prefix_of_4_to_64_characters"),
    ("fingerprint=zzzz", "fingerprint", "not_a_hex_prefix_of_4_to_64_characters"),
    ("fingerprint=%CE%B1%CE%B1%CE%B1%CE%B1", "fingerprint", "not_a_hex_prefix_of_4_to_64_characters"),
    ("fingerprint=abcd%0A", "fingerprint", "not_a_hex_prefix_of_4_to_64_characters"),
    ("fingerprint=", "fingerprint", "empty_value"),
    ("key_size=0", "key_size", "out_of_range"), ("key_size=1000001", "key_size", "out_of_range"), ("key_size=-2048", "key_size", "not_an_integer"),
    ("key_size=2048.0", "key_size", "not_an_integer"), ("key_size=", "key_size", "empty_value"),
    ("key_algorithm=", "key_algorithm", "empty_value"), ("issuer=", "issuer", "empty_value"),
    ("signature_algorithm=", "signature_algorithm", "empty_value"),
    ("issuer=" + "x" * 33001, "issuer", "too_long"),
]
SIGHTING_ONLY = [
    ("parse_status=bogus", "parse_status", "unknown_value"), ("parse_status=OK", "parse_status", "unknown_value"),
    ("parse_status=", "parse_status", "empty_value"),
    ("validity_status=valid%20", "validity_status", "unknown_value"), ("validity_status=bogus", "validity_status", "unknown_value"),
    ("format=PEM", "format", "unknown_value"), ("format=bogus", "format", "unknown_value"),
    ("chain_role=root", "chain_role", "unknown_value"), ("evidence_confidence=certain", "evidence_confidence", "unknown_value"),
    ("duplicate_kind=twice", "duplicate_kind", "unknown_value"),
    ("has_warnings=True", "has_warnings", "not_a_boolean"), ("has_warnings=TRUE", "has_warnings", "not_a_boolean"),
    ("has_warnings=1", "has_warnings", "not_a_boolean"), ("has_warnings=yes", "has_warnings", "not_a_boolean"),
    ("has_warnings=0", "has_warnings", "not_a_boolean"), ("has_warnings=", "has_warnings", "empty_value"),
    ("has_warnings=true&has_warnings=true", "has_warnings", "repeated_parameter"),
    ("scan_root=", "scan_root", "empty_value"),
]


@pytest.mark.parametrize("query,field,problem", PAGING + SORTING + SEARCH + SIGHTING_ONLY, ids=short)
def test_observation_parameters(api, run_id, query, field, problem):
    assert problems_of(api.client.get(f"/api/runs/{run_id}/fs/observations?{query}")) == [(field, problem)]


@pytest.mark.parametrize("query,field,problem", PAGING + SORTING + SEARCH, ids=short)
def test_unique_certificate_parameters(api, run_id, query, field, problem):
    assert problems_of(api.client.get(f"/api/runs/{run_id}/fs/certificates?{query}")) == [(field, problem)]


@pytest.mark.parametrize("query", ["sort=first_seq", "sort=is_ca", "sort=chain_role"])
def test_unique_view_sorts_are_limited_to_published_fields(api, run_id, query):
    assert problems_of(api.client.get(f"/api/runs/{run_id}/fs/certificates?{query}")) == [("sort", "unknown_value")]


@pytest.mark.parametrize("name", ["is_ca", "min_sightings", "parse_status", "validity_status", "format", "chain_role",
                                  "evidence_confidence", "scan_root", "has_warnings", "duplicate_kind"])
def test_the_deferred_and_sighting_only_filters_are_not_accepted_on_the_unique_view(api, run_id, name):
    assert problems_of(api.client.get(f"/api/runs/{run_id}/fs/certificates?{name}=true")) == [("query", "unknown_parameter")]


@pytest.mark.parametrize("query,field,problem", [
    ("top=0", "top", "out_of_range"), ("top=101", "top", "out_of_range"), ("top=abc", "top", "not_an_integer"),
    ("top=%D9%A5", "top", "not_an_integer"), ("top=", "top", "empty_value"), ("top=1&top=2", "top", "repeated_parameter"),
    ("top=-1", "top", "not_an_integer"), ("top=" + LONG_DIGITS, "top", "out_of_range"),
    ("frontier=-1", "frontier", "not_an_integer"), ("frontier=4611686018427387905", "frontier", "out_of_range"),
    ("frontier=", "frontier", "empty_value")])
def test_summary_parameters(api, run_id, query, field, problem):
    assert problems_of(api.client.get(f"/api/runs/{run_id}/fs/summary?{query}")) == [(field, problem)]


@pytest.mark.parametrize("query,field,problem", [
    ("top=0", "top", "out_of_range"), ("top=101", "top", "out_of_range"), ("top=x", "top", "not_an_integer"),
    ("top=", "top", "empty_value"), ("top=1&top=1", "top", "repeated_parameter")])
def test_dashboard_parameters_name_the_http_parameter_not_the_domain_one(api, query, field, problem):
    assert problems_of(api.client.get(f"/api/dashboard?{query}")) == [(field, problem)]


@pytest.mark.parametrize("query", ["recent=5", "frontier=1", "limit=1", "now=2026-01-01T00:00:00Z"])
def test_the_dashboard_has_no_other_parameters(api, query):
    assert problems_of(api.client.get(f"/api/dashboard?{query}")) == [("query", "unknown_parameter")]


@pytest.mark.parametrize("query,field,problem", [
    ("type=http", "type", "unknown_value"), ("type=FILESYSTEM", "type", "unknown_value"), ("type=", "type", "empty_value"),
    ("type=tls&type=tls", "type", "repeated_parameter"),
    ("since=2026-03-01", "since", "not_a_run_timestamp"), ("since=2026-03-01T00:00:00", "since", "not_a_run_timestamp"),
    ("since=2026-03-01T00:00:00%2B00:00", "since", "not_a_run_timestamp"), ("since=2026-03-01T00:00:00Z%0A", "since", "not_a_run_timestamp"),
    ("since=2026-03-01T00:00:00.1Z", "since", "not_a_run_timestamp"), ("since=2026-03-01T00:00:00.1234Z", "since", "not_a_run_timestamp"),
    ("since=%EF%BC%92026-03-01T00:00:00Z", "since", "not_a_run_timestamp"), ("since=%27%20OR%201%3D1%20--", "since", "not_a_run_timestamp"),
    ("since=", "since", "empty_value"), ("limit=0", "limit", "out_of_range"), ("limit=201", "limit", "out_of_range"),
    ("limit=x", "limit", "not_an_integer"), ("limit=", "limit", "empty_value")])
def test_run_statistics_parameters(api, query, field, problem):
    assert problems_of(api.client.get(f"/api/runs/stats?{query}")) == [(field, problem)]


@pytest.mark.parametrize("query", ["status=running", "offset=1", "frontier=1", "top=1"])
def test_run_statistics_has_only_its_three_parameters(api, query):
    assert problems_of(api.client.get(f"/api/runs/stats?{query}")) == [("query", "unknown_parameter")]


@pytest.mark.parametrize("query,field,problem", [
    ("limit=0", "limit", "out_of_range"), ("limit=501", "limit", "out_of_range"), ("limit=x", "limit", "not_an_integer"),
    ("offset=-1", "offset", "not_an_integer"), ("offset=10000001", "offset", "out_of_range"), ("limit=", "limit", "empty_value"),
    ("limit=1&limit=1", "limit", "repeated_parameter")])
def test_issue_parameters(api, run_id, query, field, problem):
    assert problems_of(api.client.get(f"/api/runs/{run_id}/issues?{query}")) == [(field, problem)]


@pytest.mark.parametrize("query", ["frontier=1", "kind=rejected_record", "source=agent", "sort=id"])
def test_issues_have_no_frontier_filter_or_sort(api, run_id, query):
    assert problems_of(api.client.get(f"/api/runs/{run_id}/issues?{query}")) == [("query", "unknown_parameter")]


@pytest.mark.parametrize("url", ["/api/meta", "/api/certificates/" + "a" * 64])
def test_meta_and_certificate_take_no_parameters(api, url):
    assert problems_of(api.client.get(url + "?x=1")) == [("query", "unknown_parameter")]


# =========================================================================== unknown, repeated, several at once
@pytest.mark.parametrize("name", ["bogus", "Limit", "LIMIT", "limit%20", "lim%C3%AFt", "sort[]", "limit[0]", "a.b", "%00", "x" * 300])
def test_unknown_parameters_are_refused_without_echoing_their_names(api, run_id, name):
    response = api.client.get(f"/api/runs/{run_id}/fs/observations?{name}=1")
    assert problems_of(response) == [("query", "unknown_parameter")]
    assert name not in response.text and "bogus" not in response.text


def test_several_problems_are_reported_together_and_deduplicated(api, run_id):
    found = problems_of(api.client.get(f"/api/runs/{run_id}/fs/observations?limit=abc&offset=xyz&bogus=1&other=2&has_warnings=maybe&limit=3"))
    assert sorted(found) == sorted([("limit", "repeated_parameter"), ("offset", "not_an_integer"), ("query", "unknown_parameter"),
                                    ("has_warnings", "not_a_boolean")])


def test_a_flood_of_bad_parameters_stays_bounded(api, run_id):
    query = "&".join(f"p{i}=1" for i in range(200)) + "&" + "&".join("limit=1" for _ in range(3))
    found = problems_of(api.client.get(f"/api/runs/{run_id}/fs/observations?{query}"))
    assert sorted(found) == [("limit", "repeated_parameter"), ("query", "unknown_parameter")]


@pytest.mark.parametrize("name", ["limit", "offset", "frontier", "key_size"])
def test_enormous_numbers_are_out_of_range_not_a_server_error(api, run_id, name):
    """Python refuses to turn a digit string of thousands of digits into an int: that must never become a 500."""
    response = api.client.get(f"/api/runs/{run_id}/fs/observations?{name}=" + "9" * 5000)
    assert problems_of(response) == [(name, "out_of_range")]


def test_a_valid_request_with_every_parameter_is_accepted(api, run_id):
    query = ("parse_status=ok&validity_status=valid&format=pem&chain_role=leaf&evidence_confidence=high&key_algorithm=RSA&key_size=2048"
             "&signature_algorithm=sha256WithRSAEncryption&scan_root=C%3A%5Ccerts&issuer=CN%3DAlpha%20CA&has_warnings=false"
             "&duplicate_kind=none&q=host&fingerprint=0000&sort=path&direction=desc&limit=500&offset=0&frontier=1000")
    assert api.client.get(f"/api/runs/{run_id}/fs/observations?{query}").status_code == 200


# =========================================================================== values are never echoed
def test_values_never_appear_in_error_bodies(api, run_id):
    for query in ("limit=SECRETVALUE", "parse_status=SECRETVALUE", "sort=SECRETVALUE", "fingerprint=SECRETVALUE", "has_warnings=SECRETVALUE",
                  "frontier=SECRETVALUE", "q=" + "SECRETVALUE" * 30, "direction=SECRETVALUE", "key_size=SECRETVALUE"):
        response = api.client.get(f"/api/runs/{run_id}/fs/observations?{query}")
        assert response.status_code == 422 and "SECRETVALUE" not in response.text, query
    for url in (f"/api/runs/{run_id}/fs/summary?top=SECRETVALUE", "/api/runs/stats?since=SECRETVALUE", "/api/runs/stats?type=SECRETVALUE",
                "/api/certificates/SECRETVALUE", f"/api/runs/{run_id}/issues?limit=SECRETVALUE", "/api/dashboard?top=SECRETVALUE"):
        response = api.client.get(url)
        assert response.status_code == 422 and "SECRETVALUE" not in response.text, url


# =========================================================================== validation comes first
def test_validation_is_done_before_the_run_is_looked_up(api):
    tls = api.create("tls")["run_id"]
    assert problems_of(api.client.get(f"/api/runs/{'0' * 32}/fs/observations?limit=0")) == [("limit", "out_of_range")]
    assert problems_of(api.client.get(f"/api/runs/{tls}/fs/summary?top=0")) == [("top", "out_of_range")]
    assert problems_of(api.client.get(f"/api/runs/{tls}/issues?bogus=1")) == [("query", "unknown_parameter")]


@pytest.mark.parametrize("path", ["xyz", "A" * 64, "a" * 63, "a" * 65, "a" * 63 + "G", "0" * 63 + "%0A", "%D9%A1" * 64])
def test_a_malformed_fingerprint_is_422_not_404(api, path):
    response = api.client.get(f"/api/certificates/{path}")
    assert problems_of(response) == [("sha256", "not_a_64_character_lowercase_hex_fingerprint")]


def test_a_well_formed_unknown_fingerprint_is_404(api):
    seed(api, reportfx.build_records()[:3])
    response = api.client.get("/api/certificates/" + "f" * 64)
    assert response.status_code == 404 and response.json()["error"]["code"] == "certificate_not_found"


# =========================================================================== bounds that ARE allowed
@pytest.mark.parametrize("query", ["limit=1", "limit=500", "offset=0", "offset=10000000", "frontier=0", "frontier=4611686018427387904",
                                   "key_size=1", "key_size=1000000", "q=" + "x" * 200, "fingerprint=" + "a" * 4, "fingerprint=" + "A" * 64])
def test_the_boundaries_themselves_are_accepted(api, run_id, query):
    assert api.client.get(f"/api/runs/{run_id}/fs/observations?{query}").status_code == 200
