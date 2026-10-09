"""Run issues and certificate detail at the query layer: bounds, ordering, totals and truncation, one snapshot."""
import json

import pytest

import reportfx
from backend import db, fs_ingest, reports, runs
from backend.db import TransactionRequired
from backend.reports import InvalidQuery, SightingQuery
from ingestfx import NOW, at, dir_error, running_run, sha, summary


def issues(conn, run_id, **kwargs):
    with db.read_snapshot(conn):
        return reports.list_issues(conn, run_id, **kwargs)


def detail(conn, fingerprint):
    with db.read_snapshot(conn):
        return reports.certificate_detail(conn, fingerprint)


def many_issues(conn, rejected=3, agent_errors=2):
    records = reportfx.build_records()
    run_id = reportfx.load(conn, records[:5])
    bad = [(900 + i, dict(records[0], sha256=f"bad{i}")) for i in range(rejected)]
    fs_ingest.ingest_fs_batch(conn, run_id, bad, now=at(3))
    fs_ingest.ingest_fs_batch(conn, run_id, [(0, dict(records[0], path="C:/other/place.pem"))], now=at(3))      # a sequence conflict
    errors = [dir_error(rf"C:\certs\d{i}", "listdir") for i in range(agent_errors)]
    fs_ingest.finalize_fs_run(conn, run_id, now=at(10), summary=summary(5, roots=((reportfx.ROOT_C, "scanned"),), errors=errors))
    return run_id


# =========================================================================== issues
def test_issues_come_in_insertion_order_with_a_total_and_no_internal_id(conn):
    run_id = many_issues(conn)
    page = issues(conn, run_id)
    assert page["total"] == 6 and page["limit"] == 100 and page["offset"] == 0 and len(page["items"]) == 6
    assert [(i["source"], i["kind"]) for i in page["items"]] == [("backend", "rejected_record")] * 3 + [("backend", "seq_conflict")] + [("agent", "listdir")] * 2
    assert [i["seq"] for i in page["items"]] == [900, 901, 902, 0, None, None]
    assert all(set(i) == {"source", "kind", "code", "path", "seq"} for i in page["items"])


def test_paging_through_issues_visits_each_exactly_once(conn):
    run_id = many_issues(conn, rejected=7, agent_errors=5)
    everything = issues(conn, run_id, limit=500)["items"]
    assert len(everything) == issues(conn, run_id)["total"] == 13
    for size in (1, 2, 3, 5, 13, 50):
        seen = []
        for offset in range(0, 13, size):
            seen += issues(conn, run_id, limit=size, offset=offset)["items"]
        assert seen == everything, size
    assert issues(conn, run_id, limit=5, offset=13) == {"items": [], "total": 13, "limit": 5, "offset": 13}
    assert issues(conn, run_id, limit=5, offset=10_000_000)["items"] == []


def test_paging_is_stable_while_new_issues_arrive(conn):
    records = reportfx.build_records()
    run_id = reportfx.load(conn, records[:3])
    fs_ingest.ingest_fs_batch(conn, run_id, [(800 + i, dict(records[0], sha256="bad")) for i in range(4)], now=at(3))
    first = issues(conn, run_id, limit=2)["items"]
    fs_ingest.ingest_fs_batch(conn, run_id, [(850 + i, dict(records[0], sha256="bad")) for i in range(3)], now=at(4))
    second = issues(conn, run_id, limit=2, offset=2)["items"]
    assert [i["seq"] for i in first + second] == [800, 801, 802, 803]           # nothing skipped, nothing repeated
    assert issues(conn, run_id)["total"] == 7


def test_issues_of_one_run_do_not_include_another_runs(conn):
    run_id = many_issues(conn)
    other = many_issues(conn, rejected=1, agent_errors=0)
    assert issues(conn, run_id)["total"] == 6 and issues(conn, other)["total"] == 2
    assert len(issues(conn, run_id, limit=500)["items"]) == 6
    assert [(i["source"], i["kind"]) for i in issues(conn, other, limit=500)["items"]] == [("backend", "rejected_record"), ("backend", "seq_conflict")]


def test_an_empty_run_has_no_issues(conn):
    run_id = running_run(conn)
    assert issues(conn, run_id) == {"items": [], "total": 0, "limit": 100, "offset": 0}


def test_issue_bounds(conn):
    run_id = many_issues(conn)
    for kwargs, field in ((dict(limit=0), "limit"), (dict(limit=501), "limit"), (dict(limit=-1), "limit"), (dict(limit=True), "limit"),
                          (dict(limit="5"), "limit"), (dict(limit=None), "limit"), (dict(offset=-1), "offset"),
                          (dict(offset=10_000_001), "offset"), (dict(offset=None), "offset"), (dict(offset=1.5), "offset")):
        with pytest.raises(InvalidQuery) as caught:
            issues(conn, run_id, **kwargs)
        assert caught.value.field == field, kwargs
    assert issues(conn, run_id, limit=1, offset=0)["limit"] == 1 and issues(conn, run_id, limit=500, offset=10_000_000)["items"] == []


def test_issues_need_a_snapshot_a_filesystem_run_and_an_existing_run(conn):
    run_id = many_issues(conn)
    tls = runs.create_run(conn, "tls", "manual", now=NOW)
    with pytest.raises(TransactionRequired):
        reports.list_issues(conn, run_id)
    with db.read_snapshot(conn):
        with pytest.raises(runs.RunNotFound):
            reports.list_issues(conn, "nope")
        with pytest.raises(runs.WrongRunType):
            reports.list_issues(conn, tls)


def test_issue_codes_and_paths_are_the_validated_ones(conn):
    run_id = many_issues(conn)
    for item in issues(conn, run_id)["items"]:
        assert item["code"] and (item["path"] is None or isinstance(item["path"], str))
        assert "BEGIN" not in json.dumps(item)


# =========================================================================== certificate detail: identity and runs
def test_the_identity_of_a_known_certificate(conn):
    records = reportfx.build_records()
    reportfx.load(conn, records)
    found = detail(conn, sha(7))
    expected = reportfx.unique(records)
    row = next(r for r in expected if r["sha256"] == sha(7))
    assert {k: found[k] for k in ("sha256", "serial_hex", "subject", "issuer", "san", "key_algorithm", "key_size", "key_curve",
                                  "signature_algorithm", "not_before", "not_after", "is_ca")} == \
        {"sha256": sha(7), "serial_hex": row["serial_hex"], "subject": row["subject"], "issuer": row["issuer"], "san": row["san"],
         "key_algorithm": row["key_algorithm"], "key_size": row["key_size"], "key_curve": row["key_curve"],
         "signature_algorithm": row["signature_algorithm"], "not_before": row["not_before"], "not_after": row["not_after"], "is_ca": row["is_ca"]}
    assert set(found) == {"sha256", "serial_hex", "subject", "issuer", "san", "key_algorithm", "key_size", "key_curve", "signature_algorithm",
                          "not_before", "not_after", "is_ca", "sightings_total", "runs_total", "runs_truncated", "runs"}


@pytest.mark.parametrize("n,expected", [(3, None), (4, None), (1, False), (2, True)])
def test_is_ca_is_a_boolean_or_none(conn, n, expected):
    run_id = running_run(conn)
    reportfx.load(conn, [reportfx.cert(rf"C:\a\{n}.pem", n, r"C:\a", is_ca=expected)], run_id)
    assert detail(conn, sha(n))["is_ca"] is expected


def test_unknown_and_malformed_fingerprints(conn):
    reportfx.load(conn, reportfx.build_records()[:3])
    assert detail(conn, sha(999)) is None
    for bad in ("", "xyz", "A" * 64, sha(1).upper().replace("0", "A"), "a" * 63, "a" * 65, "a" * 64 + "\n", " " + "a" * 64, "٠" * 64, sha(1)[:-1] + "g"):
        with pytest.raises(InvalidQuery) as caught:
            detail(conn, bad)
        assert caught.value.field == "sha256" and caught.value.problem == "not_a_64_character_lowercase_hex_fingerprint", repr(bad)
    for bad in (None, 5, b"a" * 64, ["a" * 64]):
        with pytest.raises(InvalidQuery) as caught:
            detail(conn, bad)
        assert caught.value.problem == "wrong_type"


def test_a_snapshot_is_required(conn):
    reportfx.load(conn, reportfx.build_records()[:3])
    with pytest.raises(TransactionRequired):
        reports.certificate_detail(conn, sha(1))


def test_runs_are_newest_first_with_exact_counts_and_totals(conn):
    records = reportfx.build_records()
    first = reportfx.load(conn, records[:14])                  # certificate 1 at one path; certificate 2 at two paths
    second = reportfx.load(conn, records[:3])
    third = reportfx.load(conn, [reportfx.pfx(r"C:\s\b.pfx", 2, r"C:\s")] * 2)             # twice inside ONE bundle
    found = detail(conn, sha(2))
    assert [r["run_id"] for r in found["runs"]] == [third, second, first]
    assert [r["run_number"] for r in found["runs"]] == sorted((r["run_number"] for r in found["runs"]), reverse=True)
    by_run = {r["run_id"]: r for r in found["runs"]}
    assert (by_run[third]["sightings"], by_run[third]["paths_count"], by_run[third]["paths"]) == (2, 1, [r"C:\s\b.pfx"])
    assert (by_run[second]["sightings"], by_run[second]["paths_count"]) == (1, 1)
    assert (by_run[first]["sightings"], by_run[first]["paths_count"]) == (2, 2)
    assert found["sightings_total"] == 5 and found["runs_total"] == 3 and found["runs_truncated"] is False
    assert found["sightings_total"] == sum(r["sightings"] for r in found["runs"])


def test_a_certificate_with_no_observations_has_empty_totals(conn):
    run_id = reportfx.load(conn, [reportfx.cert(r"C:\a\1.pem", 1, r"C:\a")])
    conn.execute("DELETE FROM fs_observations")                  # (an impossible state for the app; the query must still be well-formed)
    found = detail(conn, sha(1))
    assert (found["sightings_total"], found["runs_total"], found["runs"], found["runs_truncated"]) == (0, 0, [], False)
    assert run_id


# =========================================================================== certificate detail: truncation
@pytest.mark.parametrize("count", [1, 19, 20, 21, 25])
def test_paths_per_run_are_capped_at_twenty_with_the_full_count(conn, count):
    run_id = running_run(conn)
    paths = [rf"C:\p\{i:03d}.pem" for i in range(count)]
    reportfx.load(conn, [reportfx.cert(p, 1, r"C:\p") for p in reversed(paths)], run_id)           # inserted in the opposite order
    entry = detail(conn, sha(1))["runs"][0]
    assert entry["paths_count"] == count and entry["sightings"] == count
    assert entry["paths"] == sorted(paths)[:20] and len(entry["paths"]) == min(count, 20)
    assert entry["paths_truncated"] is (count > 20)


def test_duplicate_sightings_in_one_path_count_once_toward_paths(conn):
    run_id = running_run(conn)
    paths = [rf"C:\p\{i:03d}.pfx" for i in range(21)]
    records = [reportfx.pfx(p, 1, r"C:\p") for p in paths for _ in range(3)]                      # 21 paths, 3 sightings each
    reportfx.load(conn, records, run_id)
    entry = detail(conn, sha(1))["runs"][0]
    assert (entry["sightings"], entry["paths_count"], len(entry["paths"]), entry["paths_truncated"]) == (63, 21, 20, True)
    assert len(set(entry["paths"])) == 20


def test_the_path_list_statement_orders_explicitly(conn):
    """SQLite happens to return DISTINCT paths in sorted order today; the guarantee must come from the statement itself."""
    run_id = running_run(conn)
    reportfx.load(conn, [reportfx.cert(rf"C:\p\{i}.pem", 1, r"C:\p") for i in range(3)], run_id)
    statements = []
    conn.set_trace_callback(statements.append)
    detail(conn, sha(1))
    conn.set_trace_callback(None)
    listing = [s for s in statements if "SELECT DISTINCT path" in s]
    assert listing and all("ORDER BY path" in s for s in listing)


def test_paths_are_in_binary_order(conn):
    run_id = running_run(conn)
    paths = [r"C:\b\z.pem", r"C:\B\a.pem", r"C:\a\Z.pem", "C:\\\u00e9\\x.pem", r"C:\b\a.pem", "C:\\\u8bc1\\x.pem"]
    reportfx.load(conn, [reportfx.cert(p, 1, r"C:\x") for p in paths], run_id)
    assert detail(conn, sha(1))["runs"][0]["paths"] == sorted(paths)           # code-point order: capitals first, accents and CJK last


@pytest.mark.parametrize("count", [99, 100, 101, 120])
def test_runs_are_capped_at_one_hundred_newest_with_a_total(conn, count):
    ids = []
    for _ in range(count):
        ids.append(reportfx.load(conn, [reportfx.cert(r"C:\r\one.pem", 1, r"C:\r")]))
    found = detail(conn, sha(1))
    assert found["runs_total"] == count and found["sightings_total"] == count
    assert [r["run_id"] for r in found["runs"]] == ids[::-1][:100]
    assert found["runs_truncated"] is (count > 100)
    assert len(found["runs"]) == min(count, 100)


def test_omitted_paths_are_discoverable_through_the_observations_search(conn):
    run_id = running_run(conn)
    paths = [rf"C:\p\{i:03d}.pem" for i in range(30)]
    reportfx.load(conn, [reportfx.cert(p, 1, r"C:\p") for p in paths] + [reportfx.cert(r"C:\p\other.pem", 2, r"C:\p")], run_id)
    entry = detail(conn, sha(1))["runs"][0]
    with db.read_snapshot(conn):
        page = reports.search_sightings(conn, run_id, SightingQuery(fingerprint=sha(1), sort="path", limit=500))
    assert page.total == entry["paths_count"] == 30
    assert [i["path"] for i in page.items] == sorted(paths)
    assert set(paths) - set(entry["paths"]) <= {i["path"] for i in page.items} and len(set(paths) - set(entry["paths"])) == 10


# =========================================================================== one snapshot
def test_detail_is_one_snapshot_even_if_a_write_lands_in_the_middle(tmp_path):
    path = tmp_path / "d.db"
    writer = db.open_database(path)
    run_id = reportfx.load(writer, [reportfx.cert(rf"C:\p\{i}.pem", 1, r"C:\p") for i in range(25)])
    reader = db.connect(path, read_only=True)
    fired = []

    def intrude(statement):
        if "SELECT DISTINCT path" in statement and not fired:                        # between the totals and the path lists
            fired.append(1)
            reportfx.load(writer, [reportfx.cert(r"C:\p\late.pem", 1, r"C:\p")], run_id, start=900)
            other = running_run(writer)
            reportfx.load(writer, [reportfx.cert(r"C:\q\late.pem", 1, r"C:\q")], other)
    try:
        with db.read_snapshot(reader):
            reader.set_trace_callback(intrude)
            found = reports.certificate_detail(reader, sha(1))
            reader.set_trace_callback(None)
        assert fired
        assert (found["sightings_total"], found["runs_total"]) == (25, 1)
        assert found["runs"][0]["sightings"] == 25 and found["runs"][0]["paths_count"] == 25 and found["runs"][0]["paths_truncated"] is True
        with db.read_snapshot(reader):
            again = reports.certificate_detail(reader, sha(1))
        assert (again["sightings_total"], again["runs_total"]) == (27, 2)
    finally:
        reader.close()
        writer.close()
