"""Inventory search / filter / sort / paging over stored evidence, checked against an independent oracle (reportfx)."""
import random

import pytest

import reportfx
from backend import db, fs_ingest, fs_queries, reports, runs
from backend.fs_record import PARSE_STATUSES
from backend.reports import InvalidQuery, SightingQuery, UniqueQuery
from backend.safety import is_raw_material_name
from ingestfx import NOW, at, running_run


@pytest.fixture
def loaded(conn):
    records = reportfx.build_records()
    return conn, reportfx.load(conn, records), records


def S(conn, run_id, **kwargs):
    with db.read_snapshot(conn):
        return reports.search_sightings(conn, run_id, SightingQuery(**kwargs))


def U(conn, run_id, **kwargs):
    with db.read_snapshot(conn):
        return reports.search_unique_certificates(conn, run_id, UniqueQuery(**kwargs))


def seqs(page):
    return [item["seq"] for item in page.items]


SIGHTING_KEYS = {"seq", "entry_ordinal", "path", "filename", "scan_root", "format", "discovered_at", "sha256", "chain_index",
                 "chain_total", "chain_role", "parse_status", "detail", "access_error", "evidence_confidence",
                 "extension_mismatch", "validity_status", "days_to_expiry", "not_yet_valid", "duplicate_kind", "serial_hex",
                 "subject", "issuer", "key_algorithm", "key_size", "key_curve", "signature_algorithm", "not_before",
                 "not_after", "is_ca", "warnings", "san"}
UNIQUE_KEYS = {"sha256", "serial_hex", "subject", "issuer", "key_algorithm", "key_size", "key_curve", "signature_algorithm",
               "not_before", "not_after", "is_ca", "sightings", "paths", "first_seq", "first_path", "san"}


# =========================================================================== the dataset itself
def test_the_dataset_exercises_what_the_tests_rely_on():
    records = reportfx.build_records()
    rows = reportfx.expected(records)
    assert len(records) > 30
    assert {r["duplicate_kind"] for r in rows} == {"none", "within_file", "across_files"}
    assert {r["parse_status"] for r in rows} == {"ok", "access_denied", "read_error", "malformed", "too_large", "no_certificate", "skipped"}
    assert {r["format"] for r in rows} == {"pem", "der", "pkcs12", "unknown"}


# =========================================================================== listing
def test_the_full_listing_matches_the_oracle_field_by_field(loaded):
    conn, run_id, records = loaded
    page = S(conn, run_id, limit=500)
    oracle = reportfx.sightings(records)
    assert page.total == len(oracle) == len(page.items)
    for item, row in zip(page.items, oracle):
        for key in ("seq", "entry_ordinal", "path", "filename", "scan_root", "format", "sha256", "chain_index", "chain_total",
                    "chain_role", "parse_status", "detail", "access_error", "evidence_confidence", "validity_status",
                    "days_to_expiry", "duplicate_kind", "serial_hex", "subject", "issuer", "key_algorithm", "key_size",
                    "key_curve", "signature_algorithm", "not_before", "not_after", "is_ca", "san", "warnings",
                    "extension_mismatch", "not_yet_valid", "discovered_at"):
            assert item[key] == row[key], (item["seq"], key)


def test_items_expose_exactly_the_documented_fields_and_nothing_sensitive(loaded):
    conn, run_id, _ = loaded
    for item in S(conn, run_id, limit=500).items:
        assert set(item) == SIGHTING_KEYS
        assert not [k for k in item if is_raw_material_name(k) or "lease" in k or "token" in k]
    for item in U(conn, run_id, limit=500).items:
        assert set(item) == UNIQUE_KEYS
        assert not [k for k in item if is_raw_material_name(k) or "lease" in k or "token" in k]


def test_defaults(loaded):
    conn, run_id, records = loaded
    page = S(conn, run_id)
    assert (page.limit, page.offset, page.total) == (100, 0, len(records)) and seqs(page) == list(range(len(records)))
    assert page.frontier == len(records)                                             # ids 1..N in a fresh database


def test_a_queued_or_empty_run_gives_an_empty_page(conn):
    from backend import runs as run_module
    queued = run_module.create_run(conn, "filesystem", "manual", now=NOW)
    page = S(conn, queued)
    assert (page.items, page.total, page.frontier) == ([], 0, 0)
    assert U(conn, queued).total == 0
    started = running_run(conn)
    assert S(conn, started).total == 0


def test_unknown_and_non_filesystem_runs(conn):
    with db.read_snapshot(conn):
        with pytest.raises(runs.RunNotFound):
            reports.search_sightings(conn, "no-such-run")
        with pytest.raises(runs.RunNotFound):
            reports.search_unique_certificates(conn, "no-such-run")
    tls = runs.create_run(conn, "tls", "manual", now=NOW)
    with db.read_snapshot(conn):
        with pytest.raises(runs.WrongRunType):
            reports.search_sightings(conn, tls)
        with pytest.raises(runs.WrongRunType):
            reports.search_unique_certificates(conn, tls)


def test_runs_are_isolated_from_each_other(conn):
    first = reportfx.load(conn, reportfx.build_records()[:10])
    second = reportfx.load(conn, reportfx.build_records()[10:25])
    assert S(conn, first, limit=500).total == 10 and S(conn, second, limit=500).total == 15
    assert not set(seqs(S(conn, first, limit=500))) - set(range(10))


# =========================================================================== filters
FILTER_CASES = [
    ("parse_status", PARSE_STATUSES), ("validity_status", ("valid", "expiring", "expired")), ("format", ("pem", "der", "pkcs12", "unknown")),
    ("chain_role", ("leaf", "ca", "self_signed")), ("evidence_confidence", ("high", "medium", "low")),
    ("key_algorithm", ("RSA", "EC", "Ed25519", "DSA")), ("key_size", (2048, 3072, 4096, 256, 384, 1)),
    ("signature_algorithm", reportfx.SIGNATURES + ["md5WithRSAEncryption"]), ("scan_root", (reportfx.ROOT_C, reportfx.ROOT_D, "E:\\none")),
    ("issuer", reportfx.ISSUERS + ["CN=Nobody"]), ("has_warnings", (True, False)),
    ("duplicate_kind", ("none", "within_file", "across_files")),
]


@pytest.mark.parametrize("name, values", FILTER_CASES)
def test_each_filter_matches_the_oracle(loaded, name, values):
    conn, run_id, records = loaded
    for value in values:
        page = S(conn, run_id, limit=500, **{name: value})
        oracle = reportfx.sightings(records, **{name: value})
        assert seqs(page) == [r["seq"] for r in oracle] and page.total == len(oracle), (name, value)


def test_filters_are_exact_not_partial(loaded):
    conn, run_id, _ = loaded
    assert S(conn, run_id, issuer="CN=Alpha").total == 0 and S(conn, run_id, key_algorithm="RS").total == 0
    assert S(conn, run_id, scan_root="C:\\cert").total == 0


def test_combined_filters_are_conjunctions(loaded):
    conn, run_id, records = loaded
    kwargs = dict(parse_status="ok", key_algorithm="RSA", validity_status="valid", scan_root=reportfx.ROOT_C)
    page = S(conn, run_id, limit=500, **kwargs)
    assert seqs(page) == [r["seq"] for r in reportfx.sightings(records, **kwargs)] and page.total > 0
    assert S(conn, run_id, parse_status="access_denied", key_algorithm="RSA").total == 0        # failures have no certificate


def test_failures_have_no_certificate_attributes(loaded):
    conn, run_id, _ = loaded
    for item in S(conn, run_id, limit=500, parse_status="access_denied").items:
        assert item["sha256"] is None and item["subject"] is None and item["san"] is None and item["warnings"] == []


# =========================================================================== sorting
@pytest.mark.parametrize("sort", sorted(reports.SIGHTING_SORTS))
@pytest.mark.parametrize("direction", ["asc", "desc"])
def test_every_allowed_sort_matches_the_oracle(loaded, sort, direction):
    conn, run_id, records = loaded
    assert seqs(S(conn, run_id, limit=500, sort=sort, direction=direction)) == \
           [r["seq"] for r in reportfx.sightings(records, sort=sort, direction=direction)]


def test_nulls_sort_last_in_both_directions(loaded):
    conn, run_id, _ = loaded
    for direction in ("asc", "desc"):
        items = S(conn, run_id, limit=500, sort="key_size", direction=direction).items
        sizes = [i["key_size"] for i in items]
        first_null = sizes.index(None)
        assert all(s is None for s in sizes[first_null:]) and all(s is not None for s in sizes[:first_null])


def test_ties_break_on_seq_so_the_order_is_total(loaded):
    conn, run_id, _ = loaded
    items = S(conn, run_id, limit=500, sort="parse_status", direction="desc").items
    for a, b in zip(items, items[1:]):
        if a["parse_status"] == b["parse_status"]:
            assert a["seq"] < b["seq"]


def test_text_sorts_ignore_ascii_case(conn):
    records = [reportfx.cert(f"C:\\certs\\{name}.pem", n, "C:\\certs") for n, name in enumerate(["b", "A", "c", "B", "a"], 1)]
    run_id = reportfx.load(conn, records)
    names = [i["filename"] for i in S(conn, run_id, sort="filename").items]
    assert [n.lower() for n in names] == sorted(n.lower() for n in names) and sorted(names) != names     # not plain byte order
    assert [i["filename"] for i in S(conn, run_id, sort="filename", direction="desc").items] == names[::-1] or \
        [n.lower() for n in names[::-1]] == [i["filename"].lower() for i in S(conn, run_id, sort="filename", direction="desc").items]


# =========================================================================== paging
@pytest.mark.parametrize("limit", [1, 3, 7, 36, 37, 500])
def test_pages_cover_the_listing_exactly_once(loaded, limit):
    conn, run_id, records = loaded
    seen, offset = [], 0
    while True:
        page = S(conn, run_id, limit=limit, offset=offset, sort="subject", direction="desc")
        assert page.total == len(records) and len(page.items) <= limit
        if not page.items:
            break
        seen += seqs(page)
        offset += limit
    assert sorted(seen) == list(range(len(records))) and len(set(seen)) == len(seen)
    assert seen == [r["seq"] for r in reportfx.sightings(records, sort="subject", direction="desc")]


def test_offsets_at_and_past_the_end(loaded):
    conn, run_id, records = loaded
    total = len(records)
    assert S(conn, run_id, offset=total).items == [] and S(conn, run_id, offset=total).total == total
    assert S(conn, run_id, offset=total + 1000).total == total
    assert len(S(conn, run_id, offset=total - 1).items) == 1


def test_total_ignores_limit_and_offset_but_not_filters(loaded):
    conn, run_id, records = loaded
    totals = {S(conn, run_id, limit=limit, offset=offset, parse_status="ok").total for limit in (1, 5, 500) for offset in (0, 3, 99)}
    assert totals == {len(reportfx.sightings(records, parse_status="ok"))}


def test_random_queries_match_the_oracle(loaded):
    conn, run_id, records = loaded
    rng = random.Random(20261012)
    shas = [r["sha256"] for r in records if r["sha256"]]
    for _ in range(400):
        filters = {}
        for name, values in FILTER_CASES:
            if rng.random() < 0.18:
                filters[name] = rng.choice(list(values))
        if rng.random() < 0.3:
            filters["q"] = rng.choice(["host", "SVC", "internal", "%", "_", "\\", "é", "école", "zoë", "😀", ".com", "pfx", "bundle", "a_b", "x"])
        if rng.random() < 0.15:
            filters["fingerprint"] = rng.choice(shas)[: rng.randint(4, 64)].upper() if rng.random() < 0.5 else rng.choice(shas)[:rng.randint(4, 64)]
        sort, direction = rng.choice(sorted(reports.SIGHTING_SORTS)), rng.choice(["asc", "desc"])
        limit, offset = rng.choice([1, 3, 7, 50]), rng.choice([0, 0, 1, 5, 30])
        oracle = reportfx.sightings(records, sort=sort, direction=direction, **filters)
        page = S(conn, run_id, sort=sort, direction=direction, limit=limit, offset=offset, **filters)
        assert page.total == len(oracle), filters
        assert seqs(page) == [r["seq"] for r in oracle][offset:offset + limit], (filters, sort, direction, limit, offset)


def test_search_works_on_a_read_only_connection(tmp_path):
    path = tmp_path / "ro.db"
    writer = db.open_database(path)
    records = reportfx.build_records()
    run_id = reportfx.load(writer, records)
    reader = db.connect(path, read_only=True)
    try:
        with db.read_snapshot(reader):
            page = reports.search_sightings(reader, run_id, SightingQuery(q="host", sort="subject", limit=500))
            unique = reports.search_unique_certificates(reader, run_id, UniqueQuery(limit=500))
        assert page.total == len(reportfx.sightings(records, q="host")) and unique.total == len(reportfx.unique(records))
    finally:
        reader.close()
        writer.close()


# =========================================================================== search: escaping and case folding
def total(conn, run_id, **kwargs):
    return S(conn, run_id, limit=500, **kwargs)


def paths(page):
    return [i["path"] for i in page.items]


def test_percent_is_a_literal_not_a_wildcard(loaded):
    conn, run_id, _ = loaded
    assert paths(total(conn, run_id, q="%")) == ["D:\\data\\odd\\100%_done.pem"]
    assert paths(total(conn, run_id, q="100%_")) == ["D:\\data\\odd\\100%_done.pem"]
    assert total(conn, run_id, q="%%").total == 0 and total(conn, run_id, q="1%e").total == 0     # '%' does not mean "anything"


def test_underscore_is_a_literal_not_a_single_character_wildcard(loaded):
    conn, run_id, _ = loaded
    assert paths(total(conn, run_id, q="a_b")) == ["D:\\data\\odd\\a_b.pem"]                       # not aXb.pem
    assert paths(total(conn, run_id, q="aXb")) == ["D:\\data\\odd\\aXb.pem"]
    assert total(conn, run_id, q="a_").total == 1 and total(conn, run_id, q="_b.pem").total == 1


def test_the_escape_character_is_a_literal_too(loaded):
    conn, run_id, records = loaded
    assert total(conn, run_id, q="\\").total == len(records)                                      # every path has a backslash
    assert total(conn, run_id, q="\\odd\\").total == 9 and total(conn, run_id, q="odd\\a_b").total == 1
    assert total(conn, run_id, q="\\%").total == 0 and total(conn, run_id, q="\\_").total == 0    # not "escaped wildcard"
    assert total(conn, run_id, q="\\\\").total == 0
    assert paths(total(conn, run_id, q="\\100%")) == ["D:\\data\\odd\\100%_done.pem"]


def test_like_escape_function():
    assert reports.like_escape("a%b_c\\d") == "a\\%b\\_c\\\\d"
    assert reports.like_escape("plain") == "plain" and reports.like_escape("") == ""
    assert reports.like_escape("\\%") == "\\\\\\%"


@pytest.mark.parametrize("term", ["O'Brien", 'q"uote', "semi;colon", "dash--dash", "br[ack]et", "[", "]", "*", "?", "(", ")", "{", "}",
                                  "'; DROP TABLE runs; --", "\" OR \"1\"=\"1", "%' OR '1'='1", "1; DELETE FROM fs_observations"])
def test_special_characters_are_just_text(loaded, term):
    conn, run_id, records = loaded
    assert seqs(total(conn, run_id, q=term)) == [r["seq"] for r in reportfx.sightings(records, q=term)]
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM fs_observations").fetchone()[0] == len(records)


def test_search_is_case_insensitive_including_non_ascii(loaded):
    conn, run_id, records = loaded
    for lower, upper in (("host3", "HOST3"), ("école", "ÉCOLE"), ("ünï", "ÜNÏ"), ("zoë", "ZOË"), ("api.internal.test", "API.INTERNAL.TEST")):
        a, b = total(conn, run_id, q=lower), total(conn, run_id, q=upper)
        assert seqs(a) == seqs(b) == [r["seq"] for r in reportfx.sightings(records, q=lower)] and a.total > 0, lower
    assert paths(total(conn, run_id, q="école")) == ["D:\\data\\odd\\ÉCOLE.pem"]
    assert total(conn, run_id, q="😀").total > 0


def test_search_covers_every_documented_field(loaded):
    conn, run_id, records = loaded
    for term, field in (("bundle.pfx", "path"), ("site3.pem", "filename"), ("svc4.internal", "subject"), ("beta ca", "issuer"),
                        ("api.internal.test", "san"), ("10.0.0.9", "san"), ("zeta", "issuer")):
        page = total(conn, run_id, q=term)
        assert page.total > 0, field
        assert seqs(page) == [r["seq"] for r in reportfx.sightings(records, q=term)]


def test_search_finds_a_certificate_by_serial_number_alone(conn):
    records = [reportfx.cert("C:\\plain\\one.pem", 1, "C:\\plain", serial_hex="deadbeef01"),
               reportfx.cert("C:\\plain\\two.pem", 2, "C:\\plain", serial_hex="cafe0002")]
    run_id = reportfx.load(conn, records)
    assert paths(total(conn, run_id, q="DEADBEEF")) == ["C:\\plain\\one.pem"]
    assert paths(total(conn, run_id, q="beef01")) == ["C:\\plain\\one.pem"] and total(conn, run_id, q="0001").total == 0
    assert [i["subject"] for i in U(conn, run_id, q="cafe0002").items] == [records[1]["subject"]]


def test_search_matches_whole_values_and_fragments(loaded):
    conn, run_id, records = loaded
    assert total(conn, run_id, q="Example.COM").total == len(reportfx.sightings(records, q="example.com"))
    assert total(conn, run_id, q="CN=host1.Example.COM").total > 0 and total(conn, run_id, q="host1.example.com.").total == 0


def test_search_term_with_a_lone_surrogate_is_searched_in_its_stored_form(loaded):
    conn, run_id, _ = loaded
    assert total(conn, run_id, q="bad\ud800name").total == 0                          # stored text uses the visible escape; no crash


def test_search_bounds(loaded):
    conn, run_id, _ = loaded
    assert S(conn, run_id, q="x" * 200).total == 0
    for bad in ("", "x" * 201):
        with pytest.raises(InvalidQuery):
            SightingQuery(q=bad)
    for bad in (5, b"x", ["x"], True):
        with pytest.raises(InvalidQuery):
            SightingQuery(q=bad)


# =========================================================================== fingerprint prefix
def test_fingerprint_prefix_matches_the_start_of_the_fingerprint_only(loaded):
    conn, run_id, records = loaded
    target = reportfx.cert("x", 10)["sha256"]                                         # the fingerprint of certificate number 10
    for prefix in (target[:4], target[:32], target[:63], target, target.upper(), target[:63].upper()):
        page = total(conn, run_id, fingerprint=prefix)
        assert seqs(page) == [r["seq"] for r in reportfx.sightings(records, fingerprint=prefix)]
    assert total(conn, run_id, fingerprint=target).total == len([r for r in records if r["sha256"] == target]) > 0
    assert total(conn, run_id, fingerprint="0" * 63 + "a").total == total(conn, run_id, fingerprint=target).total
    assert total(conn, run_id, fingerprint="ffff").total == 0
    assert target.endswith("000a") and total(conn, run_id, fingerprint="000a").total == 0       # the END of a fingerprint is not a prefix
    assert total(conn, run_id, fingerprint="0" * 61 + "0a").total == 0


@pytest.mark.parametrize("bad", ["", "abc", "a" * 65, "zzzz", "%%%%", "00 00", "0000%", "_000", "0x00", 1234, b"0000", True, ["0000"]])
def test_fingerprint_must_be_a_4_to_64_character_hex_prefix(bad):
    with pytest.raises(InvalidQuery) as caught:
        SightingQuery(fingerprint=bad)
    assert caught.value.field == "fingerprint"


def test_fingerprint_and_q_combine(loaded):
    conn, run_id, records = loaded
    target = reportfx.cert("x", 3)["sha256"]
    page = total(conn, run_id, fingerprint=target[:8], q="pfx")
    assert seqs(page) == [r["seq"] for r in reportfx.sightings(records, fingerprint=target[:8], q="pfx")] and page.total > 0


# =========================================================================== validation
BAD = [
    dict(sort="path; DROP TABLE runs"), dict(sort="PATH"), dict(sort=""), dict(sort=5), dict(sort=None), dict(sort="o.seq"), dict(direction="up"),
    dict(direction="ASC"), dict(direction=None), dict(limit=0), dict(limit=501), dict(limit=-1), dict(limit=True), dict(limit="5"), dict(limit=1.5),
    dict(limit=None), dict(offset=-1), dict(offset=10_000_001), dict(offset=True), dict(offset="0"), dict(offset=None),
    dict(frontier=-1), dict(frontier=True), dict(frontier="5"), dict(frontier=2**62 + 1), dict(frontier=1.5),
    dict(parse_status="weird"), dict(parse_status=5), dict(validity_status="fine"), dict(format="jks"), dict(chain_role="root"),
    dict(evidence_confidence="certain"), dict(duplicate_kind="maybe"), dict(duplicate_kind=True),
    dict(key_size=0), dict(key_size=-1), dict(key_size=True), dict(key_size="2048"), dict(key_size=1.5), dict(key_size=10**6 + 1),
    dict(key_algorithm=""), dict(key_algorithm=5), dict(issuer=""), dict(scan_root=b"x"), dict(signature_algorithm=["x"]),
    dict(issuer="x" * 33001), dict(has_warnings="yes"), dict(has_warnings=1), dict(has_warnings=0),
]


@pytest.mark.parametrize("kwargs", BAD)
def test_invalid_sighting_queries_are_refused(kwargs):
    with pytest.raises(InvalidQuery) as caught:
        SightingQuery(**kwargs)
    assert caught.value.field in kwargs or caught.value.field in ("limit", "offset")


def test_invalid_values_are_never_echoed():
    secret = "SECRET-MARKER-123"
    for kwargs in (dict(parse_status=secret), dict(sort=secret), dict(fingerprint=secret), dict(direction=secret), dict(format=secret)):
        with pytest.raises(InvalidQuery) as caught:
            SightingQuery(**kwargs)
        assert secret not in str(caught.value) and secret not in repr(caught.value.args)


def test_unknown_parameters_are_refused():
    with pytest.raises(TypeError):
        SightingQuery(bogus=1)
    with pytest.raises(TypeError):
        UniqueQuery(parse_status="ok")


@pytest.mark.parametrize("kwargs", [dict(sort="path"), dict(sort="seq"), dict(is_ca="yes"), dict(is_ca=1), dict(min_sightings=0),
                                    dict(min_sightings=True), dict(min_sightings="2"), dict(key_size=0), dict(limit=0), dict(limit=501),
                                    dict(offset=-1), dict(frontier=-1), dict(q=""), dict(fingerprint="xyz"), dict(issuer=""), dict(direction="x")])
def test_invalid_unique_queries_are_refused(kwargs):
    with pytest.raises(InvalidQuery):
        UniqueQuery(**kwargs)


def test_valid_boundary_values_are_accepted():
    SightingQuery(limit=1, offset=0, frontier=0, key_size=1, q="x", fingerprint="abcd")
    SightingQuery(limit=500, offset=10_000_000, frontier=2**62, key_size=10**6, q="x" * 200, fingerprint="a" * 64)
    UniqueQuery(limit=500, min_sightings=10**9)


def test_queries_are_immutable_and_normalised():
    query = SightingQuery(fingerprint="ABCD")
    assert query.fingerprint == "abcd"
    with pytest.raises(Exception):
        query.limit = 5


# =========================================================================== frontier
def test_the_frontier_is_the_highest_insertion_id_in_the_snapshot(conn):
    run_id = reportfx.load(conn, reportfx.build_records()[:10])
    other = reportfx.load(conn, reportfx.build_records()[10:14])
    with db.read_snapshot(conn):
        assert reports.current_frontier(conn, run_id) == 10 and reports.current_frontier(conn, other) == 14
        assert reports.current_frontier(conn, "nope") == 0
    assert S(conn, run_id).frontier == 10 and S(conn, other).frontier == 14


def test_a_frontier_freezes_the_set_even_when_a_late_lower_sequence_row_arrives(conn):
    records = reportfx.build_records()
    run_id = reportfx.load(conn, records[:20], start=100)                              # seqs 100..119 arrive first
    first = S(conn, run_id, limit=500)
    frontier = first.frontier
    reportfx.load(conn, records[20:30], run_id, start=5)                               # LATE rows with LOWER seqs (5..14)
    frozen = S(conn, run_id, limit=500, frontier=frontier)
    assert seqs(frozen) == seqs(first) == list(range(100, 120)) and frozen.total == first.total == 20 and frozen.frontier == frontier
    live = S(conn, run_id, limit=500)
    assert live.total == 30 and seqs(live) == list(range(5, 15)) + list(range(100, 120)) and live.frontier > frontier
    assert reports.SightingQuery(frontier=frontier).frontier == frontier


def test_pages_taken_at_different_times_with_the_same_frontier_never_overlap_or_skip(conn):
    records = reportfx.build_records()
    run_id = reportfx.load(conn, records[:18], start=1000)
    frontier = S(conn, run_id).frontier
    collected = []
    for page_number in range(0, 18, 5):
        reportfx.load(conn, records[18:21], run_id, start=page_number)                  # more rows arrive between page requests
        page = S(conn, run_id, limit=5, offset=page_number, frontier=frontier, sort="path")
        assert page.total == 18
        collected += seqs(page)
    assert sorted(collected) == list(range(1000, 1018)) and len(set(collected)) == 18


def test_the_frontier_applies_to_page_and_total_alike_under_filters(conn):
    records = reportfx.build_records()
    run_id = reportfx.load(conn, records[:25])
    frontier = S(conn, run_id).frontier
    reportfx.load(conn, records[25:], run_id, start=25)
    for filters in ({}, {"parse_status": "ok"}, {"q": "host"}, {"key_algorithm": "RSA"}, {"duplicate_kind": "across_files"}):
        frozen = S(conn, run_id, limit=500, frontier=frontier, **filters)
        oracle = reportfx.sightings(records[:25], **filters)
        assert frozen.total == len(oracle) == len(frozen.items) and seqs(frozen) == [r["seq"] for r in oracle], filters
        assert S(conn, run_id, limit=2, frontier=frontier, **filters).total == frozen.total


def test_frontier_extremes(loaded):
    conn, run_id, records = loaded
    assert S(conn, run_id, frontier=0).total == 0 and S(conn, run_id, frontier=0).items == []
    assert S(conn, run_id, frontier=10**9, limit=500).total == len(records)
    assert S(conn, run_id, frontier=3, limit=500).total == 3


def test_the_frontier_does_not_freeze_the_stored_entry_ordinal(conn):
    """entry_ordinal is renumbered on a late arrival; the observation SET is frozen, this stored field is not."""
    run_id = reportfx.load(conn, [reportfx.pfx("C:\\p\\a.pfx", 1, "C:\\p")], start=100)
    frontier = S(conn, run_id).frontier
    assert S(conn, run_id, frontier=frontier).items[0]["entry_ordinal"] == 0
    reportfx.load(conn, [reportfx.pfx("C:\\p\\a.pfx", 2, "C:\\p")], run_id, start=5)    # a lower-seq row for the same file
    frozen = S(conn, run_id, frontier=frontier)
    assert [i["seq"] for i in frozen.items] == [100] and frozen.items[0]["entry_ordinal"] == 1


def test_duplicate_kind_is_derived_from_the_frozen_set_and_so_stays_stable(conn):
    run_id = reportfx.load(conn, [reportfx.cert("C:\\p\\a.pem", 1, "C:\\p")], start=100)
    frontier = S(conn, run_id).frontier
    reportfx.load(conn, [reportfx.cert("C:\\q\\b.pem", 1, "C:\\q")], run_id, start=5)  # an earlier sighting of the same fingerprint
    assert [i["duplicate_kind"] for i in S(conn, run_id, frontier=frontier).items] == ["none"]
    live = S(conn, run_id)
    assert [(i["seq"], i["duplicate_kind"]) for i in live.items] == [(5, "none"), (100, "across_files")]


def test_without_a_frontier_the_response_still_reports_the_one_it_used(conn):
    run_id = reportfx.load(conn, reportfx.build_records()[:5])
    page = S(conn, run_id)
    again = S(conn, run_id, frontier=page.frontier)
    assert seqs(again) == seqs(page) and again.frontier == page.frontier


# =========================================================================== duplicate_kind
def test_the_worked_examples_from_the_design(conn):
    def kinds(records):
        run_id = reportfx.load(conn, records)
        return [i["duplicate_kind"] for i in S(conn, run_id, limit=500).items]
    a, b = "C:\\x\\a.pfx", "C:\\x\\b.crt"
    assert kinds([reportfx.pfx(a, 1, "C:\\x"), reportfx.pfx(a, 1, "C:\\x"), reportfx.cert(b, 1, "C:\\x")]) == ["none", "within_file", "across_files"]
    assert kinds([reportfx.pfx(a, 1, "C:\\x"), reportfx.pfx(a, 1, "C:\\x"), reportfx.cert(b, 1, "C:\\x"), reportfx.cert(b, 1, "C:\\x")]) == \
        ["none", "within_file", "across_files", "within_file"]
    assert kinds([reportfx.cert(b, 1, "C:\\x"), reportfx.pfx(a, 1, "C:\\x"), reportfx.pfx(a, 1, "C:\\x")]) == ["none", "across_files", "within_file"]
    assert kinds([reportfx.cert(a, 1, "C:\\x"), reportfx.cert(a, 2, "C:\\x")]) == ["none", "none"]                   # different fingerprints


def test_records_without_a_certificate_are_never_duplicates(loaded):
    conn, run_id, _ = loaded
    kinds = {i["duplicate_kind"] for i in S(conn, run_id, limit=500, parse_status="access_denied").items}
    assert kinds == {"none"} and S(conn, run_id, duplicate_kind="none", parse_status="malformed").total == 1


def test_the_same_fingerprint_in_the_same_path_of_different_runs_is_not_a_duplicate(conn):
    first = reportfx.load(conn, [reportfx.cert("C:\\p\\a.pem", 1, "C:\\p")])
    second = reportfx.load(conn, [reportfx.cert("C:\\p\\a.pem", 1, "C:\\p")])
    assert [i["duplicate_kind"] for i in S(conn, first).items + S(conn, second).items] == ["none", "none"]


def test_categories_are_exclusive_and_reconcile_with_total_duplicates(loaded):
    conn, run_id, records = loaded
    kinds = [i["duplicate_kind"] for i in S(conn, run_id, limit=500).items]
    within, across = kinds.count("within_file"), kinds.count("across_files")
    with db.read_snapshot(conn):
        counts = fs_queries.fs_counts(conn, run_id)
    assert within + across == counts.duplicate_observations == counts.sightings - counts.unique_certificates
    assert within == counts.repeats_within_file
    assert within > 0 and across > 0
    for name in ("none", "within_file", "across_files"):
        assert S(conn, run_id, duplicate_kind=name).total == kinds.count(name)
    assert sum(S(conn, run_id, duplicate_kind=n).total for n in ("none", "within_file", "across_files")) == len(records)


def test_reconciliation_holds_for_random_datasets_and_any_arrival_order(conn):
    rng = random.Random(97)
    for trial in range(25):
        records = reportfx.random_records(rng, rng.randint(1, 40), cert_count=rng.randint(1, 6))
        order = list(range(len(records)))
        rng.shuffle(order)                                                              # seqs assigned in a random permutation ...
        seq_of = {i: order[i] for i in range(len(records))}
        run_id = running_run(conn)
        arrival = list(range(len(records)))
        rng.shuffle(arrival)                                                            # ... and arriving in yet another order
        for chunk in range(0, len(arrival), 6):
            fs_ingest.ingest_fs_batch(conn, run_id, [(seq_of[i], records[i]) for i in arrival[chunk:chunk + 6]], now=at(2))
        page = S(conn, run_id, limit=500)
        by_seq = {i["seq"]: i["duplicate_kind"] for i in page.items}
        oracle = {r["seq"]: r["duplicate_kind"] for r in reportfx.expected(records, [seq_of[i] for i in range(len(records))])}
        assert by_seq == oracle, trial
        counts = reportfx.duplicate_counts(records, [seq_of[i] for i in range(len(records))])
        kinds = list(by_seq.values())
        assert kinds.count("within_file") + kinds.count("across_files") == counts["sightings"] - counts["unique"], trial
        assert kinds.count("within_file") == counts["within_file"] and kinds.count("across_files") == counts["across_files"]
        with db.read_snapshot(conn):
            assert fs_queries.fs_counts(conn, run_id).repeats_within_file == counts["within_file"], trial


def test_the_category_counts_do_not_depend_on_the_order_of_sequence_numbers(conn):
    rng = random.Random(5)
    records = reportfx.random_records(rng, 30)
    results = set()
    for _ in range(6):
        order = list(range(len(records)))
        rng.shuffle(order)
        run_id = running_run(conn)
        fs_ingest.ingest_fs_batch(conn, run_id, [(order[i], records[i]) for i in range(len(records))], now=at(2))
        kinds = [i["duplicate_kind"] for i in S(conn, run_id, limit=500).items]
        results.add((kinds.count("within_file"), kinds.count("across_files"), kinds.count("none")))
    assert len(results) == 1


# =========================================================================== unique certificates
@pytest.mark.parametrize("sort", sorted(reports.UNIQUE_SORTS))
@pytest.mark.parametrize("direction", ["asc", "desc"])
def test_every_unique_sort_matches_the_oracle(loaded, sort, direction):
    conn, run_id, records = loaded
    page = U(conn, run_id, limit=500, sort=sort, direction=direction)
    assert [i["sha256"] for i in page.items] == [r["sha256"] for r in reportfx.unique(records, sort=sort, direction=direction)]


def test_unique_rows_match_the_oracle_field_by_field(loaded):
    conn, run_id, records = loaded
    page = U(conn, run_id, limit=500)
    oracle = reportfx.unique(records)
    assert page.total == len(oracle) == len(page.items) == 12
    for item, row in zip(page.items, oracle):
        for key in ("sha256", "serial_hex", "subject", "issuer", "key_algorithm", "key_size", "key_curve", "signature_algorithm",
                    "not_before", "not_after", "is_ca", "san", "sightings", "paths", "first_seq", "first_path"):
            assert item[key] == row[key], (item["sha256"], key)


def test_unique_view_deduplicates_by_fingerprint_but_keeps_the_sighting_counts(loaded):
    conn, run_id, records = loaded
    by_sha = {i["sha256"]: i for i in U(conn, run_id, limit=500).items}
    three = by_sha[reportfx.cert("x", 3)["sha256"]]
    assert (three["sightings"], three["paths"]) == (4, 3)                              # twice in one pfx, once in another file, once alone
    five = by_sha[reportfx.cert("x", 5)["sha256"]]
    assert (five["sightings"], five["paths"]) == (4, 3)
    assert sum(i["sightings"] for i in by_sha.values()) == len([r for r in records if r["sha256"]])


UNIQUE_FILTERS = [("key_algorithm", ("RSA", "EC", "Ed25519", "DSA")), ("key_size", (2048, 4096, 256, 1)),
                  ("signature_algorithm", reportfx.SIGNATURES), ("issuer", reportfx.ISSUERS), ("is_ca", (True, False)),
                  ("min_sightings", (1, 2, 3, 4, 5)), ("q", ("host", "pfx", "SVC", "%", "_", "école", "😀", "10.0.0", "backup", "nomatch")),
                  ("fingerprint", ("0000", "0" * 63 + "3", "0" * 62 + "0c"))]


@pytest.mark.parametrize("name, values", UNIQUE_FILTERS)
def test_each_unique_filter_matches_the_oracle(loaded, name, values):
    conn, run_id, records = loaded
    for value in values:
        page = U(conn, run_id, limit=500, **{name: value})
        oracle = reportfx.unique(records, **{name: value})
        assert [i["sha256"] for i in page.items] == [r["sha256"] for r in oracle] and page.total == len(oracle), (name, value)


def test_unique_search_also_looks_at_the_paths_a_certificate_was_seen_at(loaded):
    conn, run_id, _ = loaded
    only_by_path = U(conn, run_id, q="bundle.pfx").items
    assert {i["sha256"] for i in only_by_path} == {reportfx.cert("x", n)["sha256"] for n in (2, 3, 4)}


def test_unique_view_paging_and_frontier(conn):
    records = reportfx.build_records()
    run_id = reportfx.load(conn, records[:20], start=100)
    first = U(conn, run_id, limit=500)
    reportfx.load(conn, records[20:], run_id, start=0)                                  # late rows with lower seqs, more sightings
    frozen = U(conn, run_id, limit=500, frontier=first.frontier)
    assert [(i["sha256"], i["sightings"], i["paths"], i["first_seq"]) for i in frozen.items] == \
           [(i["sha256"], i["sightings"], i["paths"], i["first_seq"]) for i in first.items] and frozen.total == first.total
    live = U(conn, run_id, limit=500)
    assert sum(i["sightings"] for i in live.items) > sum(i["sightings"] for i in first.items)
    pages, offset = [], 0
    while True:
        page = U(conn, run_id, limit=4, offset=offset, frontier=first.frontier, sort="subject")
        if not page.items:
            break
        pages += [i["sha256"] for i in page.items]
        offset += 4
    assert sorted(pages) == sorted(i["sha256"] for i in first.items) and len(set(pages)) == len(pages)


def test_unique_frontier_freezes_the_distinct_count_and_the_first_path(conn):
    """A late arrival can add a NEW fingerprint, and a lower-seq sighting that would change an existing one's first path."""
    run_id = reportfx.load(conn, [reportfx.cert("C:\\a\\1.pem", 1, "C:\\a"), reportfx.cert("C:\\a\\2.pem", 2, "C:\\a")], start=100)
    frontier = U(conn, run_id).frontier
    reportfx.load(conn, [reportfx.cert("C:\\late\\new.pem", 99, "C:\\late"),          # seq 5: a brand-new fingerprint
                         reportfx.cert("C:\\early\\1.pem", 1, "C:\\early")],          # seq 6: earlier than fingerprint 1's seq 100
                  run_id, start=5)
    frozen = U(conn, run_id, frontier=frontier, limit=500)
    assert frozen.total == len(frozen.items) == 2
    by_sha = {i["sha256"]: i for i in frozen.items}
    one = by_sha[reportfx.cert("x", 1)["sha256"]]
    assert (one["first_path"], one["first_seq"], one["sightings"], one["paths"]) == ("C:\\a\\1.pem", 100, 1, 1)
    live = U(conn, run_id, limit=500)
    assert live.total == 3
    one = next(i for i in live.items if i["sha256"] == reportfx.cert("x", 1)["sha256"])
    assert (one["first_path"], one["first_seq"], one["sightings"], one["paths"]) == ("C:\\early\\1.pem", 6, 2, 2)


def test_unique_view_ignores_records_without_certificates(conn):
    run_id = reportfx.load(conn, [reportfx.failure("C:\\x\\a.pem", "access_denied", "C:\\x"), reportfx.cert("C:\\x\\b.pem", 1, "C:\\x")])
    assert U(conn, run_id).total == 1 and S(conn, run_id).total == 2


def test_unique_view_first_path_is_the_earliest_sighting(conn):
    records = [reportfx.cert("C:\\late\\b.pem", 1, "C:\\late"), reportfx.cert("C:\\early\\a.pem", 1, "C:\\early")]
    run_id = running_run(conn)
    fs_ingest.ingest_fs_batch(conn, run_id, [(50, records[0]), (3, records[1])], now=at(2))
    item = U(conn, run_id).items[0]
    assert (item["first_seq"], item["first_path"], item["sightings"], item["paths"]) == (3, "C:\\early\\a.pem", 2, 2)


# =========================================================================== SQL hygiene
def test_every_statement_is_parameterised_and_sorts_come_from_allowlists():
    import inspect
    source = inspect.getsource(reports)
    assert ".format(" not in source and "% (" not in source                                  # no string-built SQL
    for sort in reports.SIGHTING_SORTS.values():
        assert sort.split()[0].startswith(("o.", "c.")) and ";" not in sort and "'" not in sort
    for sort in reports.UNIQUE_SORTS.values():
        assert sort.split()[0].startswith(("c.", "g.")) and ";" not in sort and "'" not in sort


def test_searching_never_writes(tmp_path):
    path = tmp_path / "w.db"
    writer = db.open_database(path)
    run_id = reportfx.load(writer, reportfx.build_records())
    before = writer.total_changes
    reader = db.connect(path, read_only=True)
    try:
        with db.read_snapshot(reader):
            reports.search_sightings(reader, run_id, SightingQuery(q="host", limit=500))
            reports.search_unique_certificates(reader, run_id, UniqueQuery(q="host"))
    finally:
        reader.close()
    assert writer.total_changes == before
    writer.close()
