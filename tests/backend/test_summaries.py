"""The per-run summary, checked metric by metric against an independent oracle (reportfx.summary_oracle), plus its
invariants, counter comparability, frontier behaviour, validation and read-only / snapshot guarantees."""
import datetime as dt
import json
import random
import sqlite3

import pytest

import reportfx
from backend import db, fs_ingest, runs, summaries
from backend.fs_record import DEFAULT_EXPIRING_DAYS, PARSE_STATUSES, expiring_days_with_source
from backend.reports import InvalidQuery, MAX_FRONTIER
from backend.safety import is_raw_material_name
from ingestfx import NOW, at, dir_error, ok_record, running_run, summary

UTC = dt.timezone.utc
SCAN_NOW = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
NOWS = [
    SCAN_NOW,                                                       # the moment of discovery
    dt.datetime(2024, 6, 1, tzinfo=UTC),                            # before every not_before (not yet valid)
    dt.datetime(2026, 3, 10, tzinfo=UTC),                           # exactly at a not_after: 0 days, still 'expiring'
    dt.datetime(2026, 3, 10, 0, 0, 1, tzinfo=UTC),                  # one second after it: expired, -1 day
    dt.datetime(2026, 4, 15, 8, 30, tzinfo=UTC),
    dt.datetime(2026, 6, 1, tzinfo=UTC),
    dt.datetime(2028, 1, 1, tzinfo=UTC),
    dt.datetime(2040, 1, 1, tzinfo=UTC),                            # everything expired
    dt.datetime(2026, 3, 1, 14, 0, tzinfo=dt.timezone(dt.timedelta(hours=2))),    # a non-UTC aware value (== 12:00Z)
]


@pytest.fixture
def loaded(conn):
    records = reportfx.build_records()
    return conn, reportfx.load(conn, records), records


def summarize(conn, run_id, **kwargs):
    kwargs.setdefault("now", SCAN_NOW)
    with db.read_snapshot(conn):
        return summaries.fs_summary(conn, run_id, **kwargs)


OBSERVATION_BLOCKS = ("totals", "parse_status", "formats", "validity", "expiry_buckets", "algorithms", "signature_algorithms",
                      "issuers")


def assert_matches_oracle(result, oracle):
    for block in OBSERVATION_BLOCKS:
        assert result[block] == oracle[block], block
    assert result["locations"]["directories"] == oracle["locations"]["directories"]
    roots = result["locations"]["scan_roots"]
    expected_roots = oracle["locations"]["scan_roots"]
    assert (roots["top"], roots["other"], roots["total_groups"]) == (expected_roots["top"], expected_roots["other"],
                                                                       expected_roots["total_groups"])


def assert_invariants(result):
    totals = result["totals"]
    dup = totals["duplicate_observations"]
    assert dup["within_file"] + dup["across_files"] == dup["total"] == totals["sightings"] - totals["unique_certificates"]
    assert sum(result["parse_status"].values()) == totals["records"]
    assert sum(result["formats"].values()) == totals["records"]
    assert totals["sightings"] == result["parse_status"]["ok"]
    failures = sum(result["parse_status"][s] for s in summaries.FAILURE_STATUSES)
    assert totals["parse_failures"] == failures
    assert totals["records"] == totals["sightings"] + failures + totals["no_certificate"] + totals["skipped"]
    validity = result["validity"]
    assert sum(validity["at_discovery"][s] for s in ("valid", "expiring", "expired")) == totals["sightings"]
    assert sum(validity["now"]["unique"][s] for s in ("valid", "expiring", "expired")) == totals["unique_certificates"]
    assert sum(validity["now"]["sightings"][s] for s in ("valid", "expiring", "expired")) == totals["sightings"]
    buckets = result["expiry_buckets"]
    assert sum(buckets["at_discovery"].values()) == totals["sightings"]
    assert sum(buckets["now"]["unique"].values()) == totals["unique_certificates"]
    assert sum(buckets["now"]["sightings"].values()) == totals["sightings"]
    assert buckets["now"]["unique"]["expired"] == validity["now"]["unique"]["expired"]            # 'expired' is exactly the status
    assert buckets["at_discovery"]["expired"] == validity["at_discovery"]["expired"]
    for name in ("algorithms", "signature_algorithms", "issuers"):                              # disjoint groups: they add up
        ranked = result[name]
        listed_unique = sum(item["unique"] for item in ranked["top"]) + (ranked["other"]["unique"] if ranked["other"] else 0)
        listed_sightings = sum(item["sightings"] for item in ranked["top"]) + (ranked["other"]["sightings"] if ranked["other"] else 0)
        assert (listed_unique, listed_sightings) == (totals["unique_certificates"], totals["sightings"]), name
        assert len(ranked["top"]) + (ranked["other"]["groups"] if ranked["other"] else 0) == ranked["total_groups"]
        assert (ranked["other"] is None) == (ranked["total_groups"] <= len(ranked["top"]))
    directories = result["locations"]["directories"]
    other = directories["other"]["sightings"] if directories["other"] else 0
    assert sum(item["sightings"] for item in directories["top"]) + other == totals["sightings"]
    roots = result["locations"]["scan_roots"]
    assert sum(item["observations"] for item in roots["top"]) + (roots["other"]["observations"] if roots["other"] else 0) == totals["records"]


# =========================================================================== the fixed dataset against the oracle
@pytest.mark.parametrize("now", NOWS, ids=lambda n: n.isoformat())
def test_the_summary_matches_the_oracle_at_every_clock(loaded, now):
    conn, run_id, records = loaded
    result = summarize(conn, run_id, now=now)
    assert_matches_oracle(result, reportfx.summary_oracle(records, now))
    assert_invariants(result)
    assert result["as_of"] == now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


@pytest.mark.parametrize("top_n", [1, 2, 3, 5, 6, 7, 20, 100])
def test_every_top_n_cutoff_matches_the_oracle(loaded, top_n):
    conn, run_id, records = loaded
    result = summarize(conn, run_id, top_n=top_n)
    assert_matches_oracle(result, reportfx.summary_oracle(records, SCAN_NOW, top_n=top_n))
    assert_invariants(result)
    assert result["algorithms"]["limit"] == top_n


def test_the_known_numbers_of_the_fixed_dataset(loaded):
    """Hand-checked against the dataset itself (not derived from the oracle): the cheapest guard against a shared bug."""
    conn, run_id, records = loaded
    result = summarize(conn, run_id)
    assert result["totals"] == {"records": 37, "sightings": 31, "unique_certificates": 12,
                                "duplicate_observations": {"total": 19, "within_file": 2, "across_files": 17},
                                "parse_failures": 4, "no_certificate": 1, "skipped": 1}
    assert result["parse_status"]["ok"] == 31 and result["parse_status"]["access_denied"] == 1
    assert result["run"]["final"] is False and result["frontier"] == 37


def test_known_formats(loaded):
    conn, run_id, records = loaded
    formats = summarize(conn, run_id)["formats"]
    assert sum(formats.values()) == 37
    assert formats["pkcs12"] == 7 and formats["der"] == 2 and formats["unknown"] == 6
    assert formats["pem"] == 22


def test_the_other_bucket_carries_exactly_what_the_top_list_leaves_out(loaded):
    conn, run_id, records = loaded
    wide = summarize(conn, run_id, top_n=100)["issuers"]
    assert wide["other"] is None and wide["total_groups"] == 4
    narrow = summarize(conn, run_id, top_n=1)["issuers"]
    assert narrow["top"] == wide["top"][:1]
    assert narrow["other"] == {"groups": 3, "unique": sum(i["unique"] for i in wide["top"][1:]),
                               "sightings": sum(i["sightings"] for i in wide["top"][1:])}


def test_ties_are_broken_by_name_so_the_order_is_deterministic(conn):
    run_id = running_run(conn)
    # three issuers with one certificate each: the order can only come from the tie-break
    reportfx.load(conn, [reportfx.cert(rf"C:\t\{n}.pem", n, r"C:\t", issuer=name) for n, name in
                         ((1, "CN=b"), (2, "CN=a"), (3, "CN=c"))], run_id)
    names = [item["issuer"] for item in summarize(conn, run_id)["issuers"]["top"]]
    assert names == ["CN=a", "CN=b", "CN=c"]


def test_null_key_curves_sort_before_named_curves_like_the_oracle(conn):
    run_id = running_run(conn)
    reportfx.load(conn, [reportfx.cert(r"C:\t\a.pem", 1, r"C:\t", key_algorithm="EC", key_size=256, key_curve="secp256r1"),
                         reportfx.cert(r"C:\t\b.pem", 2, r"C:\t", key_algorithm="EC", key_size=256, key_curve=None)], run_id)
    items = summarize(conn, run_id)["algorithms"]["top"]
    assert [i["key_curve"] for i in items] == [None, "secp256r1"]


# =========================================================================== random datasets
@pytest.mark.parametrize("seed", range(25))
def test_random_datasets_match_the_oracle_and_keep_the_invariants(conn, seed):
    rng = random.Random(seed)
    records = reportfx.random_records(rng, rng.randint(1, 60), cert_count=rng.randint(1, 8), path_count=rng.randint(1, 6))
    seqs = rng.sample(range(0, 500), len(records))                                     # arbitrary arrival order
    run_id = running_run(conn)
    for batch_start in range(0, len(records), 9):
        chunk = list(zip(seqs[batch_start:batch_start + 9], records[batch_start:batch_start + 9]))
        fs_ingest.ingest_fs_batch(conn, run_id, chunk, now=at(2))
    now = rng.choice(NOWS)
    top_n = rng.choice([1, 2, 3, 20])
    result = summarize(conn, run_id, now=now, top_n=top_n)
    assert_matches_oracle(result, reportfx.summary_oracle(records, now, top_n=top_n, seqs=seqs))
    assert_invariants(result)


# =========================================================================== PKCS#12 bundles and duplicates
def test_a_certificate_twice_in_one_bundle_is_two_sightings_one_unique_one_within_file_duplicate(conn):
    run_id = running_run(conn)
    reportfx.load(conn, [reportfx.pfx(r"C:\s\b.pfx", 3, r"C:\s") for _ in range(2)], run_id)
    totals = summarize(conn, run_id)["totals"]
    assert (totals["sightings"], totals["unique_certificates"]) == (2, 1)
    assert totals["duplicate_observations"] == {"total": 1, "within_file": 1, "across_files": 0}


def test_the_same_certificate_in_three_files_counts_two_across_file_duplicates(conn):
    run_id = running_run(conn)
    reportfx.load(conn, [reportfx.cert(rf"C:\s\{i}.pem", 4, r"C:\s") for i in range(3)], run_id)
    assert summarize(conn, run_id)["totals"]["duplicate_observations"] == {"total": 2, "within_file": 0, "across_files": 2}


def test_a_mixed_duplicate_case_reconciles(conn):
    run_id = running_run(conn)
    records = [reportfx.pfx(r"C:\s\b.pfx", 3, r"C:\s"), reportfx.pfx(r"C:\s\b.pfx", 3, r"C:\s"), reportfx.cert(r"C:\s\c.pem", 3, r"C:\s"),
               reportfx.cert(r"C:\s\d.pem", 3, r"C:\s"), reportfx.cert(r"C:\s\d.pem", 3, r"C:\s")]
    reportfx.load(conn, records, run_id)
    dup = summarize(conn, run_id)["totals"]["duplicate_observations"]
    # 5 sightings of one certificate over 3 paths: within = (2-1) + 0 + (2-1) = 2, across = 3-1 = 2
    assert dup == {"total": 4, "within_file": 2, "across_files": 2}


# =========================================================================== scope, ordering, counters
def test_each_run_is_summarised_alone(conn):
    records = reportfx.build_records()
    first = reportfx.load(conn, records[:10])
    second = reportfx.load(conn, records[10:25])
    assert summarize(conn, first)["totals"]["records"] == 10
    assert summarize(conn, second)["totals"]["records"] == 15
    assert_matches_oracle(summarize(conn, second), reportfx.summary_oracle(records[10:25], SCAN_NOW))


def test_an_empty_run_has_a_zero_filled_summary(conn):
    run_id = running_run(conn)
    result = summarize(conn, run_id)
    assert result["totals"] == {"records": 0, "sightings": 0, "unique_certificates": 0,
                                "duplicate_observations": {"total": 0, "within_file": 0, "across_files": 0},
                                "parse_failures": 0, "no_certificate": 0, "skipped": 0}
    assert set(result["parse_status"]) == set(PARSE_STATUSES) and not any(result["parse_status"].values())
    assert result["frontier"] == 0
    for name in ("algorithms", "signature_algorithms", "issuers"):
        assert result[name] == {"top": [], "other": None, "total_groups": 0, "limit": 20}
    assert result["locations"]["directories"]["top"] == [] and result["locations"]["scan_roots"]["top"] == []
    assert_invariants(result)


def test_a_queued_run_can_be_summarised(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    result = summarize(conn, run_id)
    assert result["run"]["status"] == "queued" and result["run"]["final"] is False and result["totals"]["records"] == 0


def test_the_zero_filled_shape_does_not_depend_on_the_data(loaded):
    conn, run_id, _ = loaded
    empty = running_run(conn)
    full_result, empty_result = summarize(conn, run_id), summarize(conn, empty)
    for block in ("totals", "parse_status", "formats", "validity", "expiry_buckets", "issues", "frontier_scope"):
        assert _walk_keys(full_result[block], set()) == _walk_keys(empty_result[block], set()), block


def test_run_facts_and_final_per_status(conn):
    records = reportfx.build_records()[:5]
    run_id = reportfx.load(conn, records)
    running = summarize(conn, run_id)["run"]
    assert running["status"] == "running" and running["final"] is False and running["finished_at"] is None
    fs_ingest.finalize_fs_run(conn, run_id, now=at(10), summary=summary(5, roots=((reportfx.ROOT_C, "scanned"),)))
    done = summarize(conn, run_id)["run"]
    assert done["status"] in ("completed", "partial") and done["final"] is True and done["finished_at"]

    failed = running_run(conn)
    fs_ingest.finalize_fs_run(conn, failed, now=at(11), outcome="failed", fatal_code="boom")
    failed_run = summarize(conn, failed)["run"]
    assert failed_run["status"] == "failed" and failed_run["final"] is True
    assert set(done) == {"run_id", "run_number", "type", "status", "final", "started_at", "finished_at"}


def test_run_counters_agree_with_the_summary_like_for_like(conn):
    records = reportfx.build_records()
    run_id = reportfx.load(conn, records)
    bad = [(500, dict(records[0], sha256="not-a-hash")), (501, dict(records[1], unknown_field=1))]
    result = fs_ingest.ingest_fs_batch(conn, run_id, bad, now=at(3))
    assert len(result.rejected) == 2
    conflict = fs_ingest.ingest_fs_batch(conn, run_id, [(0, dict(records[0], path=r"C:\certs\moved.pem"))], now=at(3))
    assert len(conflict.conflicts) == 1
    errors = [dir_error(r"C:\certs\private", "listdir"), dir_error(r"C:\gone", "root"), dir_error(r"C:\certs\vanished.pem", "read", "PermissionError:WinError 5"),
              dir_error(rf"{reportfx.ROOT_C}\locked1.pem", "read", "PermissionError:WinError 5")]
    fs_ingest.finalize_fs_run(conn, run_id, now=at(10),
                              summary=summary(len(records), roots=((reportfx.ROOT_C, "scanned"), (reportfx.ROOT_D, "scanned")), errors=errors))
    row = conn.execute("SELECT record_count, finding_count, rejected_count, error_count FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    result = summarize(conn, run_id)
    issues = result["issues"]
    assert result["totals"]["records"] == row["record_count"]
    assert result["totals"]["sightings"] == row["finding_count"]
    assert issues["rejected"] == row["rejected_count"] == 2
    assert issues["errors"]["total"] == row["error_count"]
    assert issues["errors"]["total"] == sum(issues["errors"][k] for k in ("file_errors", "directory_errors", "unresolved_read_errors"))
    assert issues["errors"]["directory_errors"] == 2 and issues["errors"]["unresolved_read_errors"] == 1
    assert issues["errors"]["file_errors"] == 2                                       # the stored access_denied + read_error rows
    assert issues["seq_conflicts"] == 1


def test_parse_failures_and_unique_are_reported_but_never_forced_equal_to_a_run_counter(conn):
    records = reportfx.build_records()
    run_id = reportfx.load(conn, records)
    fs_ingest.finalize_fs_run(conn, run_id, now=at(10), summary=summary(len(records), roots=((reportfx.ROOT_C, "scanned"), (reportfx.ROOT_D, "scanned"))))
    row = conn.execute("SELECT record_count, finding_count, error_count FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    totals = summarize(conn, run_id)["totals"]
    assert totals["parse_failures"] == 4 and row["error_count"] == 2                   # different definitions: access_denied + read_error only
    assert totals["unique_certificates"] == 12 and totals["unique_certificates"] not in (row["record_count"], row["finding_count"])


def test_a_resolved_read_error_is_counted_once(conn):
    run_id = running_run(conn)
    failing = reportfx.failure(r"C:\s\locked.pem", "access_denied", r"C:\s")
    fs_ingest.ingest_fs_batch(conn, run_id, [(0, failing)], now=at(2))
    fs_ingest.finalize_fs_run(conn, run_id, now=at(10), summary=summary(1, roots=((r"C:\s", "scanned"),),
                              errors=[dir_error(r"C:\s\locked.pem", "read", failing["access_error"])]))
    errors = summarize(conn, run_id)["issues"]["errors"]
    assert errors == {"total": 1, "file_errors": 1, "directory_errors": 0, "unresolved_read_errors": 0}
    assert conn.execute("SELECT error_count FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0] == 1


# =========================================================================== the frontier
def test_a_frontier_freezes_every_observation_block_while_late_lower_seq_rows_arrive(conn):
    records = reportfx.build_records()
    run_id = reportfx.load(conn, records[:20], start=100)
    first = summarize(conn, run_id)
    reportfx.load(conn, records[20:30], run_id, start=5)
    frozen = summarize(conn, run_id, frontier=first["frontier"])
    for block in (*OBSERVATION_BLOCKS, "locations"):
        assert frozen[block] == first[block], block
    assert frozen["frontier"] == first["frontier"]
    assert_matches_oracle(frozen, reportfx.summary_oracle(records[:20], SCAN_NOW, seqs=range(100, 120)))
    live = summarize(conn, run_id)
    assert live["totals"]["records"] == 30 and live["frontier"] > first["frontier"]
    assert_matches_oracle(live, reportfx.summary_oracle(records[:30], SCAN_NOW, seqs=list(range(100, 120)) + list(range(5, 15))))


def test_frontier_extremes(loaded):
    conn, run_id, records = loaded
    assert summarize(conn, run_id, frontier=0)["totals"]["records"] == 0
    assert summarize(conn, run_id, frontier=10**9)["totals"]["records"] == 37
    assert summarize(conn, run_id, frontier=3)["totals"]["records"] == 3
    assert summarize(conn, run_id, frontier=3)["frontier"] == 3
    assert summarize(conn, run_id, frontier=MAX_FRONTIER)["totals"]["records"] == 37


def test_the_frontier_is_scoped_to_the_run(conn):
    records = reportfx.build_records()
    first = reportfx.load(conn, records[:10])
    second = reportfx.load(conn, records[10:20])
    assert summarize(conn, second, frontier=10)["totals"]["records"] == 0             # ids 1..10 belong to the other run
    assert summarize(conn, first, frontier=10)["totals"]["records"] == 10


def test_the_live_issue_counters_move_even_under_a_frozen_frontier(conn):
    records = reportfx.build_records()
    run_id = reportfx.load(conn, records)
    frontier = summarize(conn, run_id)["frontier"]
    before = summarize(conn, run_id, frontier=frontier)
    fs_ingest.ingest_fs_batch(conn, run_id, [(900, dict(records[0], sha256="bad"))], now=at(3))
    fs_ingest.finalize_fs_run(conn, run_id, now=at(10), summary=summary(len(records), roots=((reportfx.ROOT_C, "scanned"), (reportfx.ROOT_D, "scanned")),
                                                                         errors=[dir_error()]))
    after = summarize(conn, run_id, frontier=frontier)
    for block in (*OBSERVATION_BLOCKS, "locations"):
        assert after[block] == before[block]
    assert before["issues"]["rejected"] == 0 and after["issues"]["rejected"] == 1
    assert before["issues"]["errors"]["directory_errors"] == 0 and after["issues"]["errors"]["directory_errors"] == 1
    assert after["issues"]["errors"]["file_errors"] == before["issues"]["errors"]["file_errors"]
    assert set(summaries.FRONTIER_SCOPE["live"]) == {"issues.errors.directory_errors", "issues.errors.unresolved_read_errors",
                                                     "issues.rejected", "issues.seq_conflicts"}


# =========================================================================== expiring_days and 'now'
def test_a_run_without_a_configured_threshold_uses_the_agent_default(loaded):
    conn, run_id, _ = loaded
    assert summarize(conn, run_id)["expiring_days"] == {"value": DEFAULT_EXPIRING_DAYS, "source": "default"}


def test_a_run_with_a_configured_threshold_uses_it_and_says_so(conn):
    run_id = running_run(conn, config={"expiring_days": 60})
    records = reportfx.build_records()
    reportfx.load(conn, records, run_id)
    now = dt.datetime(2026, 4, 15, 8, 30, tzinfo=UTC)                                  # 2026-06-01 is 46 days away: valid at 30, expiring at 60
    result = summarize(conn, run_id, now=now)
    assert result["expiring_days"] == {"value": 60, "source": "run_config"}
    assert_matches_oracle(result, reportfx.summary_oracle(records, now, threshold=60))
    default = summarize(conn, reportfx.load(conn, records), now=now)
    assert result["validity"]["now"]["unique"]["expiring"] > default["validity"]["now"]["unique"]["expiring"]


def test_a_configured_zero_threshold_is_a_real_value(conn):
    run_id = running_run(conn, config={"expiring_days": 0})
    records = [reportfx.cert(r"C:\s\a.pem", 1, r"C:\s", validity_status="valid")]    # not_after 2026-03-10: 9 days at discovery
    reportfx.load(conn, records, run_id)
    result = summarize(conn, run_id, now=dt.datetime(2026, 3, 10, tzinfo=UTC))
    assert result["expiring_days"] == {"value": 0, "source": "run_config"}
    assert result["validity"]["now"]["unique"]["expiring"] == 1                         # 0 days left is still <= 0
    assert summarize(conn, run_id, now=dt.datetime(2026, 3, 9, tzinfo=UTC))["validity"]["now"]["unique"]["valid"] == 1


@pytest.mark.parametrize("config", [{"expiring_days": True}, {"expiring_days": "30"}, {"expiring_days": -1}, {"expiring_days": 10**7 + 1},
                                    {"expiring_days": None}, {"other": 1}])
def test_an_unusable_stored_threshold_falls_back_to_the_default(config):
    """The stored configuration is immutable (a trigger), so the fallback is checked on the function the summary uses."""
    assert expiring_days_with_source(config) == (DEFAULT_EXPIRING_DAYS, "default")
    assert expiring_days_with_source("not a mapping") == (DEFAULT_EXPIRING_DAYS, "default")


def test_the_run_configuration_cannot_be_edited_after_creation(conn):
    run_id = running_run(conn, config={"expiring_days": 60})
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE runs SET config_json = '{}' WHERE run_id = ?", (run_id,))
    assert summarize(conn, run_id)["expiring_days"]["value"] == 60


def test_now_is_the_injected_clock_not_the_wall_clock(loaded):
    conn, run_id, _ = loaded
    past, future = summarize(conn, run_id, now=NOWS[1]), summarize(conn, run_id, now=NOWS[7])
    assert past["validity"]["now"]["unique"]["not_yet_valid"] == 12 and future["validity"]["now"]["unique"]["expired"] == 12
    assert past["validity"]["now"]["unique"]["expired"] == 0 and past["as_of"].startswith("2024-06-01")
    assert future["validity"]["at_discovery"] == summarize(conn, run_id)["validity"]["at_discovery"]       # stored evidence never moves


def test_the_clock_boundary_second_flips_expired(conn):
    run_id = running_run(conn)
    reportfx.load(conn, [reportfx.cert(r"C:\s\a.pem", 1, r"C:\s")], run_id)            # not_after = 2026-03-10T00:00:00Z
    edge = summarize(conn, run_id, now=dt.datetime(2026, 3, 10, tzinfo=UTC))
    after = summarize(conn, run_id, now=dt.datetime(2026, 3, 10, 0, 0, 1, tzinfo=UTC))
    assert edge["validity"]["now"]["unique"]["expiring"] == 1 and edge["expiry_buckets"]["now"]["unique"]["0-30"] == 1
    assert after["validity"]["now"]["unique"]["expired"] == 1 and after["expiry_buckets"]["now"]["unique"]["expired"] == 1


@pytest.mark.parametrize("days,bucket", [(-400, "expired"), (-1, "expired"), (0, "0-30"), (30, "0-30"), (31, "31-90"), (90, "31-90"),
                                         (91, "91-365"), (365, "91-365"), (366, "over-365"), (10**6, "over-365")])
def test_bucket_boundaries(days, bucket):
    assert summaries.expiry_bucket(days) == bucket == reportfx.bucket(days)


def test_the_sql_buckets_use_the_same_boundaries_as_the_python_function(conn):
    boundary_days = [-1, 0, 30, 31, 90, 91, 365, 366]
    sql = summaries._BUCKET_SQL.format(d="?")
    for days in boundary_days:
        assert conn.execute(f"SELECT {sql}", (days, ) * sql.count("?")).fetchone()[0] == summaries.expiry_bucket(days)


def test_stored_discovery_buckets_match_the_oracle_for_boundary_values(conn):
    """Certificates whose days-to-expiry at discovery sit exactly on the bucket boundaries."""
    run_id = running_run(conn)
    day = dt.timedelta(days=1)
    records = []
    for n, offset in enumerate([-1, 0, 30, 31, 90, 91, 365, 366], start=1):
        not_after = (SCAN_NOW + offset * day).strftime("%Y-%m-%dT%H:%M:%SZ")
        records.append(reportfx.cert(rf"C:\b\{n}.pem", n, r"C:\b", not_after=not_after))
    reportfx.load(conn, records, run_id)
    result = summarize(conn, run_id)
    assert result["expiry_buckets"]["at_discovery"] == {"expired": 1, "0-30": 2, "31-90": 2, "91-365": 2, "over-365": 1}
    assert_matches_oracle(result, reportfx.summary_oracle(records, SCAN_NOW))


def test_not_yet_valid_is_a_separate_count_not_a_status(conn):
    run_id = running_run(conn)
    records = [reportfx.cert(r"C:\s\a.pem", 1, r"C:\s", not_before="2027-01-01T00:00:00Z", not_after="2030-01-01T00:00:00Z"),
               reportfx.cert(r"C:\s\b.pem", 2, r"C:\s")]
    reportfx.load(conn, records, run_id)
    validity = summarize(conn, run_id)["validity"]
    assert validity["at_discovery"]["not_yet_valid"] == 1
    assert sum(validity["at_discovery"][s] for s in ("valid", "expiring", "expired")) == 2


# =========================================================================== locations
def test_directories_are_the_stored_path_up_to_the_last_backslash(conn):
    run_id = running_run(conn)
    records = [reportfx.cert(r"C:\a\b\one.pem", 1, r"C:\a"), reportfx.cert(r"C:\a\b\two.pem", 2, r"C:\a"),
               reportfx.cert(r"C:\a\C\x.pem", 3, r"C:\a"), reportfx.cert(r"c:\a\b\case.pem", 4, r"c:\a"),
               reportfx.cert(r"C:\top.pem", 5, "C:"), reportfx.cert("D:\\ünï\\证书\\é.pem", 6, "D:\\ünï")]
    reportfx.load(conn, records, run_id)
    top = {item["directory"]: item["sightings"] for item in summarize(conn, run_id)["locations"]["directories"]["top"]}
    assert top == {"C:\\a\\b\\": 2, "C:\\a\\C\\": 1, "c:\\a\\b\\": 1, "C:\\": 1, "D:\\ünï\\证书\\": 1}      # no case folding


def test_failed_files_have_no_directory_entry_but_do_have_a_scan_root_entry(loaded):
    conn, run_id, records = loaded
    locations = summarize(conn, run_id, top_n=100)["locations"]
    assert sum(item["sightings"] for item in locations["directories"]["top"]) == 31
    roots = {item["scan_root"]: item for item in locations["scan_roots"]["top"]}
    assert roots[reportfx.ROOT_C]["observations"] > 0 and sum(r["observations"] for r in roots.values()) == 37


def test_scan_root_other_bucket_does_not_pretend_unique_counts_add_up(loaded):
    conn, run_id, _ = loaded
    roots = summarize(conn, run_id)["locations"]["scan_roots"]
    assert roots["other"] is None and roots["limit"] == summaries.MAX_TOP
    # a certificate seen under two roots is unique in each: per-root unique counts overlap by design
    assert sum(item["unique"] for item in roots["top"]) > summarize(conn, run_id)["totals"]["unique_certificates"]


def test_the_directory_other_bucket_has_no_unique_count(loaded):
    conn, run_id, _ = loaded
    other = summarize(conn, run_id, top_n=2)["locations"]["directories"]["other"]
    assert set(other) == {"groups", "sightings"}


# =========================================================================== errors and validation
def test_unknown_and_wrong_type_runs(conn):
    tls = runs.create_run(conn, "tls", "manual", now=NOW)
    with db.read_snapshot(conn):
        with pytest.raises(runs.RunNotFound):
            summaries.fs_summary(conn, "nope", now=SCAN_NOW)
        with pytest.raises(runs.WrongRunType):
            summaries.fs_summary(conn, tls, now=SCAN_NOW)


def test_a_summary_needs_a_snapshot(loaded):
    conn, run_id, _ = loaded
    from backend.db import TransactionRequired
    with pytest.raises(TransactionRequired):
        summaries.fs_summary(conn, run_id, now=SCAN_NOW)
    with pytest.raises(TransactionRequired):
        summaries.run_statistics(conn)
    with pytest.raises(TransactionRequired):
        summaries.dashboard(conn, now=SCAN_NOW)


@pytest.mark.parametrize("kwargs,field,problem", [
    (dict(now=dt.datetime(2026, 3, 1)), "now", "needs_a_timezone"), (dict(now="2026-03-01"), "now", "wrong_type"),
    (dict(now=None), "now", "wrong_type"),
    (dict(top_n=0), "top_n", "out_of_range"), (dict(top_n=101), "top_n", "out_of_range"), (dict(top_n=-5), "top_n", "out_of_range"),
    (dict(top_n=True), "top_n", "wrong_type"), (dict(top_n="5"), "top_n", "wrong_type"), (dict(top_n=2.0), "top_n", "wrong_type"),
    (dict(top_n=None), "top_n", "wrong_type"),
    (dict(frontier=-1), "frontier", "out_of_range"), (dict(frontier=MAX_FRONTIER + 1), "frontier", "out_of_range"),
    (dict(frontier=True), "frontier", "wrong_type"), (dict(frontier="3"), "frontier", "wrong_type"), (dict(frontier=1.5), "frontier", "wrong_type")])
def test_bad_parameters_are_refused_with_a_fixed_problem_code(loaded, kwargs, field, problem):
    conn, run_id, _ = loaded
    with db.read_snapshot(conn):
        with pytest.raises(InvalidQuery) as caught:
            summaries.fs_summary(conn, run_id, **{"now": SCAN_NOW, **kwargs})
    assert (caught.value.field, caught.value.problem) == (field, problem)


def test_validation_happens_before_the_run_is_looked_up(conn):
    with db.read_snapshot(conn):
        with pytest.raises(InvalidQuery):
            summaries.fs_summary(conn, "nope", now=SCAN_NOW, top_n=0)


def test_the_parameter_values_never_appear_in_the_error_text(loaded):
    conn, run_id, _ = loaded
    with db.read_snapshot(conn):
        with pytest.raises(InvalidQuery) as caught:
            summaries.fs_summary(conn, run_id, now=SCAN_NOW, frontier=-123456)
    assert "123456" not in str(caught.value)


def test_top_n_extremes_are_accepted(loaded):
    conn, run_id, _ = loaded
    assert summarize(conn, run_id, top_n=1)["issuers"]["limit"] == 1
    assert summarize(conn, run_id, top_n=summaries.MAX_TOP)["issuers"]["limit"] == 100


# =========================================================================== read-only, snapshot and secrecy
def test_the_summary_works_on_a_read_only_connection_and_writes_nothing(tmp_path):
    path = tmp_path / "ro.db"
    writer = db.open_database(path)
    records = reportfx.build_records()
    run_id = reportfx.load(writer, records)
    reader = db.connect(path, read_only=True)
    try:
        before = writer.execute("PRAGMA data_version").fetchone()[0]
        with db.read_snapshot(reader):
            result = summaries.fs_summary(reader, run_id, now=SCAN_NOW)
            assert reader.in_transaction
        assert not reader.in_transaction
        assert_matches_oracle(result, reportfx.summary_oracle(records, SCAN_NOW))
        assert writer.execute("PRAGMA data_version").fetchone()[0] == before
    finally:
        reader.close()
        writer.close()


def test_one_summary_is_one_snapshot_even_if_a_write_lands_in_the_middle(tmp_path):
    path = tmp_path / "snap.db"
    writer = db.open_database(path)
    records = reportfx.build_records()
    run_id = reportfx.load(writer, records)
    reader = db.connect(path, read_only=True)
    fired = []

    def intrude(statement):
        if "JOIN certificates" in statement and not fired:                           # in the middle of the summary ...
            fired.append(1)
            reportfx.load(writer, [reportfx.cert(r"C:\late\x.pem", 1, r"C:\late")], run_id, start=900)
            fs_ingest.ingest_fs_batch(writer, run_id, [(901, dict(records[0], sha256="bad"))], now=at(3))
    try:
        with db.read_snapshot(reader):
            reader.set_trace_callback(intrude)
            result = summaries.fs_summary(reader, run_id, now=SCAN_NOW)
            reader.set_trace_callback(None)
        assert fired
        assert_matches_oracle(result, reportfx.summary_oracle(records, SCAN_NOW))
        assert_invariants(result)
        assert result["issues"]["rejected"] == 0                                      # the live counters come from the same snapshot too
        assert summarize_on(reader, run_id)["totals"]["records"] == len(records) + 1
    finally:
        reader.close()
        writer.close()


def summarize_on(conn, run_id):
    with db.read_snapshot(conn):
        return summaries.fs_summary(conn, run_id, now=SCAN_NOW)


def _walk_keys(value, found):
    if isinstance(value, dict):
        for key, inner in value.items():
            found.add(key)
            _walk_keys(inner, found)
    elif isinstance(value, list):
        for inner in value:
            _walk_keys(inner, found)
    return found


def test_the_response_contract_has_fixed_keys_and_no_raw_material(loaded):
    conn, run_id, _ = loaded
    result = summarize(conn, run_id, top_n=3)
    assert list(result) == ["run", "as_of", "frontier", "frontier_scope", "expiring_days", "totals", "parse_status", "formats",
                            "validity", "expiry_buckets", "algorithms", "signature_algorithms", "issuers", "locations", "issues"]
    assert set(result["totals"]) == {"records", "sightings", "unique_certificates", "duplicate_observations", "parse_failures",
                                     "no_certificate", "skipped"}
    assert set(result["issues"]) == {"errors", "rejected", "seq_conflicts"}
    assert set(result["algorithms"]) == {"top", "other", "total_groups", "limit"}
    assert set(result["algorithms"]["top"][0]) == {"key_algorithm", "key_size", "key_curve", "unique", "sightings"}
    assert set(result["issuers"]["top"][0]) == {"issuer", "unique", "sightings"}
    assert set(result["locations"]["directories"]["top"][0]) == {"directory", "sightings", "unique"}
    assert set(result["locations"]["scan_roots"]["top"][0]) == {"scan_root", "observations", "sightings", "unique"}
    format_names = {"pem", "der", "pkcs12", "unknown"}                                   # values of a closed list, used as keys of `formats`
    assert [k for k in _walk_keys(result, set()) if is_raw_material_name(k) and k not in format_names] == []
    blob = json.dumps(result)
    assert "uniq" not in _walk_keys(result, set()) and "PRIVATE KEY" not in blob and "BEGIN" not in blob


def test_the_summary_is_json_serialisable_and_deterministic(loaded):
    conn, run_id, _ = loaded
    first = json.dumps(summarize(conn, run_id), sort_keys=True)
    assert first == json.dumps(summarize(conn, run_id), sort_keys=True)


def test_other_runs_data_never_leaks_in(conn):
    records = reportfx.build_records()
    mine = reportfx.load(conn, records[:12])
    reportfx.load(conn, [reportfx.cert(r"E:\other\z.pem", 99, r"E:\other", issuer="CN=Leak")])
    result = summarize(conn, mine)
    assert "CN=Leak" not in json.dumps(result) and "E:" not in json.dumps(result)


def test_a_single_row_run(conn):
    run_id = running_run(conn)
    fs_ingest.ingest_fs_batch(conn, run_id, [(0, ok_record(r"C:\only\one.pem", 1))], now=at(2))
    result = summarize(conn, run_id)
    assert result["totals"]["records"] == result["totals"]["sightings"] == result["totals"]["unique_certificates"] == 1
    assert result["issuers"]["top"] == [{"issuer": "CN=Test CA", "unique": 1, "sightings": 1}] and result["issuers"]["other"] is None


# =========================================================================== added after mutation testing
def test_file_errors_are_frozen_by_the_frontier_and_skipped_is_not_no_certificate(conn):
    run_id = running_run(conn)
    first = [reportfx.failure(r"C:\m\skip1.pem", "skipped", r"C:\m", detail="cloud_placeholder", access_error=None),
             reportfx.failure(r"C:\m\skip2.pem", "skipped", r"C:\m", detail="cloud_placeholder", access_error=None),
             reportfx.failure(r"C:\m\nocert.pem", "no_certificate", r"C:\m", detail="no_certificate_block", access_error=None),
             reportfx.failure(r"C:\m\locked.pem", "access_denied", r"C:\m")]
    reportfx.load(conn, first, run_id)
    before = summarize(conn, run_id)
    assert before["totals"]["skipped"] == 2 and before["totals"]["no_certificate"] == 1
    assert before["issues"]["errors"]["file_errors"] == 1
    reportfx.load(conn, [reportfx.failure(r"C:\m\late.pem", "access_denied", r"C:\m")], run_id, start=50)
    frozen = summarize(conn, run_id, frontier=before["frontier"])
    assert frozen["issues"]["errors"]["file_errors"] == 1 and frozen["totals"] == before["totals"]
    assert summarize(conn, run_id)["issues"]["errors"]["file_errors"] == 2


def test_assess_at_needs_an_aware_clock_and_follows_the_agents_rules():
    from backend.fs_record import assess_at
    with pytest.raises(ValueError):
        assess_at("2025-01-01T00:00:00Z", "2026-03-10T00:00:00Z", dt.datetime(2026, 3, 1), 30)
    aware = dt.datetime(2026, 3, 1, 12, tzinfo=UTC)
    assert assess_at("2025-01-01T00:00:00Z", "2026-03-10T00:00:00Z", aware, 30) == ("expiring", 8, False)
    assert assess_at("2025-01-01T00:00:00Z", "2026-03-10T00:00:00Z", aware, 7) == ("valid", 8, False)
    assert assess_at("2027-01-01T00:00:00Z", "2030-01-01T00:00:00Z", aware, 30)[2] is True


def _tied_run(conn):
    """Four certificates, every ranked dimension tied on both unique-certificate and sighting counts, inserted in
    an order that is the REVERSE of the expected name order."""
    run_id = running_run(conn)
    names = ["d", "c", "b", "a"]
    records = [reportfx.cert(rf"C:\tie\{name}\f.pem", n, rf"C:\tie{name}", issuer=f"CN={name}", signature_algorithm=f"sig-{name}",
                             key_algorithm=f"alg-{name}", key_size=2048, key_curve=None)
               for n, name in enumerate(names, start=1)]
    reportfx.load(conn, records, run_id)
    return run_id


def test_tied_groups_come_out_in_name_order_end_to_end(conn):
    run_id = _tied_run(conn)
    result = summarize(conn, run_id)
    assert [i["issuer"] for i in result["issuers"]["top"]] == ["CN=a", "CN=b", "CN=c", "CN=d"]
    assert [i["signature_algorithm"] for i in result["signature_algorithms"]["top"]] == ["sig-a", "sig-b", "sig-c", "sig-d"]
    assert [i["key_algorithm"] for i in result["algorithms"]["top"]] == ["alg-a", "alg-b", "alg-c", "alg-d"]
    assert [i["scan_root"] for i in result["locations"]["scan_roots"]["top"]] == [r"C:\tie" + n for n in "abcd"]
    assert [i["directory"] for i in result["locations"]["directories"]["top"]] == ["C:\\tie\\" + n + "\\" for n in "abcd"]
    assert all(item["unique"] == 1 and item["sightings"] == 1 for item in result["issuers"]["top"])
    assert [i["issuer"] for i in summarize(conn, run_id, top_n=2)["issuers"]["top"]] == ["CN=a", "CN=b"]   # and so is who falls into 'other'


# SQL promises no order among rows that tie on the earlier ORDER BY keys, and a real GROUP BY happens to emit groups in
# name order, so no data can show a missing tie-break. These tests therefore feed each REAL ordering constant a group
# set that arrives in the opposite order, which is exactly what an engine is allowed to do.
TIE_CASES = [
    ("ORDER_ISSUERS", ["issuer"], ["uniq", "sightings"]),
    ("ORDER_SIGNATURES", ["signature_algorithm"], ["uniq", "sightings"]),
    ("ORDER_ALGORITHMS", ["key_algorithm", "key_size", "key_curve"], ["uniq", "sightings"]),
    ("ORDER_SCAN_ROOTS", ["scan_root"], ["observations", "sightings"]),
    ("ORDER_DIRECTORIES", ["directory"], ["sightings", "uniq"]),
]


def _arrival_reversed(keys, measures, values):
    """A group query whose rows arrive in the given order, every measure equal."""
    row = lambda value: ", ".join([*(f"{'NULL' if v is None else repr(v)} AS {k}" for k, v in zip(keys, value)), *(f"1 AS {m}" for m in measures)])   # noqa: E731
    return " UNION ALL ".join(f"SELECT {row(value)}" for value in values)


@pytest.mark.parametrize("order_name,keys,measures", TIE_CASES)
def test_every_ranking_breaks_ties_by_name_regardless_of_arrival_order(conn, order_name, keys, measures):
    order = getattr(summaries, order_name)
    names = ["a", "b", "c", "d"]
    values = [tuple(n if k != "key_size" else 1 for k in keys) for n in reversed(names)]          # arrives d, c, b, a
    values = [tuple(2048 if k == "key_size" else None if k == "key_curve" else v for k, v in zip(keys, row)) for row in values]
    group_sql = _arrival_reversed(keys, measures, values)
    ranked = summaries._ranked(conn, group_sql, {}, order, 10, (measures[-1],))
    assert [item[keys[0]] for item in ranked["top"]] == names


def test_the_ordering_constants_end_with_the_group_name():
    assert summaries.ORDER_ISSUERS.endswith("issuer") and summaries.ORDER_SIGNATURES.endswith("signature_algorithm")
    assert summaries.ORDER_ALGORITHMS.endswith("key_algorithm, key_size, key_curve")
    assert summaries.ORDER_SCAN_ROOTS.endswith("scan_root") and summaries.ORDER_DIRECTORIES.endswith("directory")


# =========================================================================== evidence for the mutants judged unobservable
def _two_refusals(conn):
    records = reportfx.build_records()
    run_id = reportfx.load(conn, records[:5])
    fs_ingest.ingest_fs_batch(conn, run_id, [(500, dict(records[0], sha256="bad")), (501, dict(records[1], sha256="bad"))], now=at(3))
    fs_ingest.ingest_fs_batch(conn, run_id, [(0, dict(records[0], path="C:/moved/a.pem"))], now=at(3))        # seq 0 re-sent, contradicting
    return run_id


def test_a_replayed_refusal_or_conflict_adds_no_issue_row(conn):
    """The application writes at most one issue row per (run, kind, seq): the lookup runs inside the same write
    transaction as the insert, so even a replay inside ONE batch finds the row the first copy just wrote."""
    run_id = _two_refusals(conn)
    records = reportfx.build_records()
    again = [(500, dict(records[0], sha256="bad")), (500, dict(records[0], sha256="bad")), (0, dict(records[0], path="C:/other/a.pem")),
             (0, dict(records[0], path="C:/other/b.pem"))]
    fs_ingest.ingest_fs_batch(conn, run_id, again, now=at(4))
    rows = [tuple(r) for r in conn.execute("SELECT kind, seq, COUNT(*) FROM run_issues WHERE source = 'backend' GROUP BY kind, seq ORDER BY kind, seq")]
    assert rows == [("rejected_record", 500, 1), ("rejected_record", 501, 1), ("seq_conflict", 0, 1)]


def test_the_summary_counts_distinct_sequence_numbers_even_if_issue_rows_repeat(conn):
    """The database does NOT forbid repeated issue rows (idx_run_issues_kind_seq is deliberately non-unique); only the
    ingestion code prevents them. The run counter counts DISTINCT seqs, so the summary must too, or the two would
    disagree the moment a second writer, a repair script or a bug produced a duplicate row."""
    run_id = _two_refusals(conn)
    for kind, seq in (("rejected_record", 500), ("rejected_record", 500), ("seq_conflict", 0), ("seq_conflict", 0)):
        conn.execute("INSERT INTO run_issues (run_id, source, kind, code, seq) VALUES (?, 'backend', ?, 'x', ?)", (run_id, kind, seq))
    issues = summarize(conn, run_id)["issues"]
    assert issues["rejected"] == 2 and issues["seq_conflicts"] == 1
    assert issues["rejected"] == fs_ingest.derived_counts(conn, run_id).rejected == 2
    assert issues["seq_conflicts"] == fs_ingest.seq_conflict_count(conn, run_id) == 1


def test_only_certificate_sightings_have_a_validity_status_so_the_null_group_never_reaches_the_counts(conn):
    """The table forbids a status without a certificate and a certificate without a status, so the rows excluded
    from the at-discovery counts are exactly the non-sightings, and an unexpected key could not be added to them."""
    run_id = reportfx.load(conn, reportfx.build_records())
    assert conn.execute("SELECT COUNT(*) FROM fs_observations WHERE (sha256 IS NULL) != (validity_status IS NULL)").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM fs_observations WHERE validity_status IS NULL").fetchone()[0] == 6
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE fs_observations SET validity_status = 'bogus' WHERE run_id = ?", (run_id,))
    assert summaries._counts([(None, 6), ("valid", 2), ("surprise", 9)], ("valid", "expiring", "expired")) == \
        {"valid": 2, "expiring": 0, "expired": 0}
    result = summarize(conn, run_id)["validity"]["at_discovery"]
    assert set(result) == {"valid", "expiring", "expired", "not_yet_valid"}
    assert sum(result[s] for s in ("valid", "expiring", "expired")) == 31


@pytest.mark.parametrize("offset_hours", [-11, -5, 0, 2, 5.5, 14])
def test_the_same_instant_gives_the_same_summary_in_any_timezone(loaded, offset_hours):
    """Aware datetimes subtract by instant and the timestamp formatter converts to UTC, so the response cannot depend
    on the offset the caller used."""
    conn, run_id, _ = loaded
    utc_now = dt.datetime(2026, 4, 15, 8, 30, tzinfo=UTC)
    local = utc_now.astimezone(dt.timezone(dt.timedelta(hours=offset_hours)))
    assert local == utc_now
    assert summarize(conn, run_id, now=local) == summarize(conn, run_id, now=utc_now)
    assert summarize(conn, run_id, now=local)["as_of"] == "2026-04-15T08:30:00.000Z"
