"""Regression tests for the Phase 2b review fixes.

F1 strict patterns (no trailing newline / non-ASCII digits)      F2 integrity-warning alignment with the SQLite CHECK
F3 summary numeric hardening                                     F4 rejected-lookup index (migration 0002) and cost
S1 requested-root reconciliation                                 S3 JSON-style (list) batch pairs
plus a validator-versus-database agreement check: no record may get past Python validation and then fail a CHECK.
"""
import itertools
import json
import os
import random
import sqlite3

import pytest

import pemgen
import pfxgen
from backend import db, fs_ingest, fs_queries, fs_record, run_state as rs, runs
from backend.fs_record import RecordRejected, parse_summary, validate_fs_record
from ingestfx import (NOW, STAMP, at, dir_error, failure_record, finish, ingest, ok_record, pfx_record, running_run,
                      sha, summary)
from treegen import put, run_scan

WARNING = "pkcs12_integrity_not_verified"


def stored_count(conn, table="fs_observations"):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def rejection(record) -> str:
    with pytest.raises(RecordRejected) as info:
        validate_fs_record(record)
    return info.value.code


# =========================================================================== F1: strict patterns
SUFFIXES = ["\n", "\r\n", "\n\n", " ", "\t", "\x00", "\u2028"]


@pytest.mark.parametrize("suffix", SUFFIXES)
@pytest.mark.parametrize("field, code", [("sha256", "bad_sha256"), ("serial_hex", "bad_serial_hex"),
                                         ("discovered_at", "bad_discovered_at"), ("not_before", "bad_not_before"),
                                         ("not_after", "bad_not_after")])
def test_trailing_characters_on_strict_fields_are_validation_errors(field, code, suffix):
    record = ok_record(n=1)
    record[field] = record[field] + suffix
    assert rejection(record) == code


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_trailing_characters_on_access_error_and_warnings_are_validation_errors(suffix):
    assert rejection(failure_record(access_error="PermissionError:WinError 5" + suffix)) == "bad_access_error"
    assert rejection(ok_record(n=1, warnings=["serial_not_positive" + suffix])) == "bad_warnings"


@pytest.mark.parametrize("field, value", [("sha256", "\n" + "a" * 64), ("serial_hex", "\n01"), ("warnings", ["\nx"])])
def test_leading_newlines_are_rejected_too(field, value):
    record = ok_record(n=1)
    record[field] = value
    rejection(record)


@pytest.mark.parametrize("pattern, good, bad", [
    (fs_record._SHA256, "a" * 64, "a" * 64 + "\n"),
    (fs_record._SERIAL, "-0f", "0f\n"),
    (fs_record._WARNING, "serial_not_positive", "serial_not_positive\n"),
    (fs_record._ACCESS_ERROR, "PermissionError:WinError 5", "PermissionError:WinError 5\n"),
    (fs_record._TIMESTAMP, STAMP, STAMP + "\n"),
    (fs_record._STOP_REASON, "time_limit", "time_limit\n"),
    (rs._CODE, "agent_failed", "agent_failed\n"),
    (db._MIGRATION_NAME, "0001_initial.sql", "0001_initial.sql\n"),
])
def test_every_pattern_is_fully_anchored(pattern, good, bad):
    assert pattern.fullmatch(good) and pattern.fullmatch(bad) is None


def test_patterns_are_ascii_only():
    assert fs_record._TIMESTAMP.fullmatch("٢٠٢٦-٠٣-٠١T١٢:٠٠:٠٠Z") is None            # Arabic-Indic digits
    assert fs_record._ACCESS_ERROR.fullmatch("PermissionError:WinError ٥") is None
    assert db._MIGRATION_NAME.fullmatch("٠٠٠١_initial.sql") is None


def test_no_pattern_in_the_backend_still_uses_end_anchor_or_match():
    import pathlib
    import re
    for path in pathlib.Path(fs_record.__file__).parent.glob("*.py"):
        code = [line for line in path.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#")]
        assert not [line for line in code if re.search(r're\.compile\(r".*\$"\)', line)], path.name
        assert not [line for line in code if re.search(r"_(SHA256|SERIAL|WARNING|ACCESS_ERROR|TIMESTAMP|STOP_REASON|CODE)\.match\(", line)], path.name


def test_trailing_newline_records_never_reach_sqlite(conn):
    run_id = running_run(conn)
    bad = [ok_record(r"C:\a\1.pem", n=1, sha256=sha(1) + "\n"), ok_record(r"C:\a\2.pem", n=2, serial_hex="01\n"),
           ok_record(r"C:\a\3.pem", n=3, warnings=["x\n"]), failure_record(r"C:\a\4.pem", access_error="PermissionError:WinError 5\n"),
           ok_record(r"C:\a\5.pem", n=5, not_after=STAMP + "\n")]
    good = [ok_record(r"C:\a\ok1.pem", n=10), ok_record(r"C:\a\ok2.pem", n=11)]
    result = ingest(conn, run_id, [good[0], *bad, good[1]])                      # no IntegrityError may escape
    assert result.accepted == 2
    assert result.rejected == ((1, "bad_sha256"), (2, "bad_serial_hex"), (3, "bad_warnings"), (4, "bad_access_error"),
                               (5, "bad_not_after"))
    assert [o["path"] for o in fs_queries.list_fs_observations(conn, run_id)] == [r"C:\a\ok1.pem", r"C:\a\ok2.pem"]
    assert stored_count(conn, "certificates") == 2 and not conn.in_transaction


def test_summary_codes_with_trailing_newlines_are_not_trusted(conn):
    assert parse_summary(summary(1, stop_reason="completed\n")) is None
    facts = parse_summary(summary(1, errors=[dir_error(code="PermissionError:WinError 5\n")]))
    assert facts.errors == () and facts.invalid_errors == 1
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    final = finish(conn, run_id, 1, summary=summary(1, stop_reason="completed\n"))
    assert final.status == "partial" and final.error_summary == "stop_reason_missing"


def test_run_state_codes_with_trailing_newlines_are_sanitised():
    run = rs.start(rs.new_run(NOW), at(1))
    assert rs.fail(run, at(2), "boom\n").error_summary == "failed"
    assert rs.fail(run, at(2), "boom").error_summary == "boom"
    status, reasons = rs.decide_outcome(rs.Counts(records=1), rs.AgentReport(outcome="failed", fatal_code="boom\n"))
    assert (status, reasons) == ("failed", ("agent_failed",))
    status, reasons = rs.decide_outcome(rs.Counts(records=1), rs.AgentReport(
        outcome="finished", stop_reason="time_limit\n", coverage_started=True))
    assert reasons == ("stopped_unknown",)
    done = rs.finish(run, at(3), rs.Counts(records=1), rs.AgentReport(outcome="finished", stop_reason="time_limit\n",
                                                                       coverage_started=True))
    assert done.stop_reason is None and "\n" not in (done.error_summary or "")


# =========================================================================== F2: integrity warning alignment
def test_exact_integrity_warning_with_high_confidence_is_rejected():
    assert rejection(pfx_record(warnings=[WARNING], evidence_confidence="high")) == "integrity_warning_with_high_confidence"


def test_integrity_warning_with_medium_confidence_is_accepted():
    valid = validate_fs_record(pfx_record(warnings=[WARNING], evidence_confidence="medium"))
    assert valid.observation["warnings_json"] == f'["{WARNING}"]' and valid.observation["evidence_confidence"] == "medium"


@pytest.mark.parametrize("warning", ["x" + WARNING + "x", WARNING + "_extra", "pre_" + WARNING, "x" + WARNING, WARNING + "9"])
def test_substrings_of_the_integrity_warning_are_rejected_cleanly_at_high_confidence(warning):
    high = dict(evidence_confidence="high")
    assert rejection(pfx_record(warnings=[warning], **high)) == "integrity_warning_with_high_confidence"
    assert rejection(pfx_record(warnings=["serial_not_positive", warning], **high)) == "integrity_warning_with_high_confidence"


def test_substring_warnings_are_fine_below_high_confidence():
    valid = validate_fs_record(pfx_record(warnings=["x" + WARNING + "x"], evidence_confidence="medium"))
    assert valid.observation["evidence_confidence"] == "medium"


def test_no_integrity_error_escapes_for_malformed_integrity_records(conn):
    run_id = running_run(conn)
    records = [pfx_record(r"C:\a\1.pfx", n=1, warnings=["x" + WARNING + "x"], evidence_confidence="high"),
               pfx_record(r"C:\a\2.pfx", n=2, warnings=[WARNING], evidence_confidence="high"),
               pfx_record(r"C:\a\3.pfx", n=3, warnings=[WARNING + "_v2"], evidence_confidence="high"),
               pfx_record(r"C:\a\4.pfx", n=4, warnings=[WARNING], evidence_confidence="medium"),
               ok_record(r"C:\a\good.pem", n=9)]
    result = ingest(conn, run_id, records)
    assert result.accepted == 2
    assert [c for _, c in result.rejected] == ["integrity_warning_with_high_confidence"] * 3
    assert {o["filename"] for o in fs_queries.list_fs_observations(conn, run_id)} == {"4.pfx", "good.pem"}


def test_the_database_constraint_itself_is_unchanged(conn):
    run_id = running_run(conn)
    sql = conn.execute("SELECT sql FROM sqlite_master WHERE name = 'fs_observations'").fetchone()[0]
    assert "instr(warnings_json, 'pkcs12_integrity_not_verified') = 0 OR evidence_confidence <> 'high'" in sql
    with pytest.raises(sqlite3.IntegrityError):                                    # bypassing Python still fails in SQLite
        conn.execute("INSERT INTO fs_observations (run_id, seq, entry_ordinal, path, filename, scan_root, format, "
                     "discovered_at, parse_status, evidence_confidence, warnings_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                     (run_id, 0, 0, "C:\\p", "p", "C:\\", "pkcs12", STAMP, "access_denied", "high", f'["x{WARNING}x"]'))


# =========================================================================== F3: summary numerics
NON_FINITE = [float("nan"), float("inf"), float("-inf")]


@pytest.mark.parametrize("value", NON_FINITE)
def test_non_finite_elapsed_seconds_makes_the_summary_unusable(value):
    assert parse_summary(summary(1, elapsed_seconds=value)) is None


@pytest.mark.parametrize("value", NON_FINITE)
@pytest.mark.parametrize("where", ["records_by_status", "skipped", "unknown_key", "nested_root", "error_entry"])
def test_non_finite_floats_anywhere_make_the_summary_unusable(where, value):
    raw = summary(1)
    if where == "records_by_status":
        raw["records_by_status"] = {"ok": value}
    elif where == "skipped":
        raw["skipped"] = {"cloud_placeholder": value}
    elif where == "unknown_key":
        raw["something_else"] = {"deep": [1, [2, value]]}
    elif where == "nested_root":
        raw["roots"][0]["extra"] = value
    else:
        raw["errors"] = [dict(dir_error(), extra=value)]
    assert parse_summary(raw) is None


def test_self_referencing_summary_terminates_and_is_unusable():
    raw = summary(1)
    raw["loop"] = raw
    assert parse_summary(raw) is None


def test_canonical_json_rejects_non_finite_values():
    for value in NON_FINITE:
        for payload in (value, [value], {"a": value}):
            with pytest.raises(ValueError):
                fs_record.canonical_json(payload)
    assert fs_record.canonical_json({"b": 1, "a": [1.5, None]}) == '{"a":[1.5,null],"b":1}'


def test_finite_but_implausible_numbers_are_dropped_not_stored():
    facts = parse_summary(summary(1, elapsed_seconds=-5, files_read=10**13, directories_visited=True))
    assert facts is not None
    assert facts.stored["elapsed_seconds"] is None and facts.stored["files_read"] is None
    assert facts.stored["directories_visited"] is None
    assert parse_summary(summary(1, elapsed_seconds=1e308)).stored["elapsed_seconds"] is None
    assert parse_summary(summary(1, elapsed_seconds=12.5)).stored["elapsed_seconds"] == 12.5


def test_stored_summary_size_is_bounded(monkeypatch):
    assert parse_summary(summary(1)) is not None
    monkeypatch.setattr(fs_record, "MAX_SUMMARY_JSON", 200)
    assert parse_summary(summary(1)) is None


def test_the_real_size_bound_covers_the_largest_possible_stored_summary():
    big = summary(1, roots=[("R:\\" + "x" * 30000 + str(i), "scanned") for i in range(fs_record.MAX_ROOTS)])
    facts = parse_summary(big)
    assert facts is not None and len(fs_record.canonical_json(facts.stored)) <= fs_record.MAX_SUMMARY_JSON
    assert max(len(r["root"]) for r in facts.stored["roots"]) == fs_record.MAX_STORED_ROOT
    assert all(len(r) > fs_record.MAX_STORED_ROOT for r in facts.reported_roots)       # reconciliation keeps the full text
    assert parse_summary(summary(1, roots=[("C:\\a", "scanned")] * (fs_record.MAX_ROOTS + 1))) is None


@pytest.mark.parametrize("bad", [dict(elapsed_seconds=float("nan")), dict(elapsed_seconds=float("inf")),
                                 dict(records_by_status={"ok": float("nan")}), dict(extra={"x": [float("-inf")]})])
def test_malformed_numeric_summaries_never_leave_the_run_running(conn, bad):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), ok_record(r"C:\app\2.pem", n=2)])
    final = finish(conn, run_id, 2, summary=summary(2, **bad))                      # must not raise
    stored = runs.get_run(conn, run_id)
    assert final.status == stored["status"] == "partial" and stored["status"] != "running"
    assert final.error_summary == "stop_reason_missing" and stored["finished_at"] is not None
    assert stored["agent_summary"] is None and (stored["record_count"], stored["finding_count"]) == (2, 2)
    assert [(i["source"], i["code"]) for i in fs_queries.list_run_issues(conn, run_id)] == [("backend", "summary_invalid")]


def test_numeric_hardening_also_holds_for_summaries_that_went_through_json(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    wire = json.loads(json.dumps(summary(1, elapsed_seconds=float("nan")), allow_nan=True))     # json.loads accepts NaN
    assert wire["elapsed_seconds"] != wire["elapsed_seconds"]
    assert finish(conn, run_id, 1, summary=wire).status == "partial"
    assert runs.get_run(conn, run_id)["status"] == "partial"


def test_a_failed_run_with_a_broken_summary_still_ends(conn):
    run_id = running_run(conn)
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(5), outcome="failed", fatal_code="scan_crashed",
                                      summary=summary(0, elapsed_seconds=float("inf")))
    assert final.status == "failed" and runs.get_run(conn, run_id)["status"] == "failed"


def test_a_valid_summary_is_still_stored_with_finite_numbers(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1)])
    assert finish(conn, run_id, 1, summary=summary(1, elapsed_seconds=2.25)).status == "completed"
    assert runs.get_run(conn, run_id)["agent_summary"]["elapsed_seconds"] == 2.25


# =========================================================================== F4: migration 0002 and the rejected lookup
def index_columns(conn, name):
    table = conn.execute("SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?", (name,)).fetchone()[0]
    assert table
    return [r["name"] for r in conn.execute(f"PRAGMA index_info({name})")]


def plan(conn, sql, params):
    return " | ".join(r["detail"] for r in conn.execute("EXPLAIN QUERY PLAN " + sql, params))


def test_migration_0002_exists_and_is_applied(conn):
    assert [name for _, name, _ in db._migrations()] == ["0001_initial.sql", "0002_run_issues_lookup.sql"]
    assert db.latest_version() == 2 == db.schema_version(conn)
    assert index_columns(conn, "idx_run_issues_kind_seq") == ["run_id", "kind", "seq"]


def test_the_rejected_lookup_uses_the_new_index(conn):
    detail = plan(conn, fs_ingest.REJECTED_LOOKUP_SQL, ("r", "rejected_record", 3))
    assert "idx_run_issues_kind_seq" in detail and "run_id=? AND kind=? AND seq=?" in detail
    assert "SCAN" not in detail and "idx_run_issues_run" not in detail


def test_the_ingest_path_runs_the_indexed_lookup_statement(conn):
    seen = []
    run_id = running_run(conn)
    conn.set_trace_callback(seen.append)
    ingest(conn, run_id, [{"junk": 1}])
    conn.set_trace_callback(None)
    prefix = fs_ingest.REJECTED_LOOKUP_SQL.split("?")[0]
    assert any(statement.startswith(prefix) and statement.endswith("LIMIT 1") for statement in seen)


def test_upgrade_from_version_1_keeps_data_and_adds_the_index(tmp_path, monkeypatch):
    real = db.MIGRATIONS_DIR
    old = tmp_path / "v1"
    old.mkdir()
    (old / "0001_initial.sql").write_text((real / "0001_initial.sql").read_text(encoding="utf-8"), encoding="utf-8")
    path = tmp_path / "upgrade.db"
    monkeypatch.setattr(db, "MIGRATIONS_DIR", old)
    conn = db.open_database(path)
    assert db.schema_version(conn) == 1
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), {"junk": 1}])
    conn.close()
    monkeypatch.setattr(db, "MIGRATIONS_DIR", real)
    conn = db.open_database(path)
    try:
        assert db.schema_version(conn) == 2 and index_columns(conn, "idx_run_issues_kind_seq") == ["run_id", "kind", "seq"]
        assert stored_count(conn) == 1 and stored_count(conn, "run_issues") == 1
        assert fs_ingest._seq_was_rejected(conn, run_id, 1) and not fs_ingest._seq_was_rejected(conn, run_id, 0)
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()


def vm_steps(n_rejected: int, per_batch: int | None = None) -> int:
    """SQLite virtual-machine progress callbacks used to ingest n records that are all rejected (deterministic, unlike time)."""
    conn = db.open_database(":memory:")
    try:
        run_id = running_run(conn)
        steps = [0]

        def tick():
            steps[0] += 1
            return 0
        conn.set_progress_handler(tick, 100)
        records = [(i, {"junk": i}) for i in range(n_rejected)]
        size = per_batch or n_rejected
        for start in range(0, n_rejected, size):
            result = fs_ingest.ingest_fs_batch(conn, run_id, records[start:start + size], now=at(2))
            assert len(result.rejected) == len(records[start:start + size])
        return steps[0]
    finally:
        conn.close()


def test_rejected_record_ingestion_is_not_quadratic():
    small, large = vm_steps(1000), vm_steps(4000)
    ratio = large / small
    assert ratio < 6, f"4x the records cost {ratio:.1f}x the work (linear ~4, quadratic ~16)"


def test_rejected_record_ingestion_stays_linear_across_many_batches():
    small, large = vm_steps(1000, per_batch=100), vm_steps(4000, per_batch=100)
    assert large / small < 8


def test_first_write_wins_and_idempotency_survive_the_index(conn):
    run_id = running_run(conn)
    first = ingest(conn, run_id, [{"junk": 1}, ok_record(n=2)])
    again = ingest(conn, run_id, [{"junk": 1}, ok_record(n=2)])
    assert first.rejected == ((0, "unknown_field"),) and again == fs_ingest.BatchResult(0, 2, ())
    assert ingest(conn, run_id, [ok_record(n=3)], start=0) == fs_ingest.BatchResult(0, 1, ())        # rejected seq stays rejected
    assert stored_count(conn, "run_issues") == 1


# =========================================================================== S1: configured-root reconciliation
def roots_run(conn, roots, records=1):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": roots} if roots is not None else {})
    runs.start_run(conn, run_id, now=at(1))
    ingest(conn, run_id, [ok_record(rf"C:\app\{i}.pem", n=i + 1) for i in range(records)])
    return run_id


def test_all_configured_roots_reported_means_no_downgrade(conn):
    run_id = roots_run(conn, [r"C:\app", r"D:\data"])
    final = finish(conn, run_id, 1, summary=summary(1, roots=((r"C:\app", "scanned"), (r"D:\data", "scanned"))))
    assert final.status == "completed" and final.error_summary is None


def test_a_configured_root_missing_from_the_summary_is_partial(conn):
    run_id = roots_run(conn, [r"C:\app", r"D:\data"])
    final = finish(conn, run_id, 1, summary=summary(1, roots=((r"C:\app", "scanned"),)))
    assert final.status == "partial" and final.error_summary == "roots_not_scanned:1"


def test_several_missing_roots_are_counted(conn):
    run_id = roots_run(conn, [r"C:\app", r"D:\one", r"E:\two"])
    final = finish(conn, run_id, 1, summary=summary(1, roots=((r"C:\app", "scanned"),)))
    assert final.error_summary == "roots_not_scanned:2"


def test_missing_roots_add_to_roots_reported_with_a_bad_status(conn):
    run_id = roots_run(conn, [r"C:\app", r"D:\gone", r"E:\missing"])
    final = finish(conn, run_id, 1, summary=summary(1, roots=((r"C:\app", "scanned"), (r"D:\gone", "not_found"))))
    assert final.status == "partial" and final.error_summary == "roots_not_scanned:2"


def test_roots_are_compared_after_phase_1_normalisation(conn):
    run_id = roots_run(conn, ["C:/app/", r"D:\data\\sub\..\data"])
    final = finish(conn, run_id, 1, summary=summary(1, roots=((r"C:\app", "scanned"), (r"D:\data\data", "scanned"))))
    assert final.status == "completed"


@pytest.mark.skipif(os.name != "nt", reason="Windows paths are case-insensitive")
def test_roots_are_compared_case_insensitively_on_windows(conn):
    run_id = roots_run(conn, [r"c:\APP"])
    assert finish(conn, run_id, 1, summary=summary(1, roots=((r"C:\app", "scanned"),))).status == "completed"


def test_a_root_listed_twice_in_the_request_is_one_root(conn):
    run_id = roots_run(conn, [r"C:\app", r"C:\app"])
    reported = ((r"C:\app", "scanned"), (r"C:\app", "overlap"))                      # what Phase 1 reports for a duplicate root
    assert finish(conn, run_id, 1, summary=summary(1, roots=reported)).status == "completed"


def test_a_root_reported_as_overlap_counts_as_reported(conn):
    run_id = roots_run(conn, [r"C:\app", r"C:\app\sub"])
    final = finish(conn, run_id, 1, summary=summary(1, roots=((r"C:\app", "scanned"), (r"C:\app\sub", "overlap"))))
    assert final.status == "completed"


def test_reporting_only_the_overlapped_root_is_still_a_gap_for_the_other(conn):
    run_id = roots_run(conn, [r"C:\app", r"C:\app\sub"])
    final = finish(conn, run_id, 1, summary=summary(1, roots=((r"C:\app\sub", "scanned"),)))
    assert final.status == "partial" and final.error_summary == "roots_not_scanned:1"


def test_extra_reported_roots_are_not_a_gap(conn):
    run_id = roots_run(conn, [r"C:\app"])
    assert finish(conn, run_id, 1, summary=summary(1, roots=((r"C:\app", "scanned"), (r"X:\unrequested", "scanned")))).status == "completed"


def test_a_missing_root_requested_twice_is_counted_once(conn):
    run_id = roots_run(conn, [r"C:\app", r"D:\gone", r"D:\gone", "D:/gone/"])
    final = finish(conn, run_id, 1, summary=summary(1, roots=((r"C:\app", "scanned"),)))
    assert final.status == "partial" and final.error_summary == "roots_not_scanned:1"


def test_unreported_roots_counts_distinct_normalised_roots():
    assert fs_record.unreported_roots((r"D:\gone", r"D:\gone", "D:/gone/"), ()) == 1
    assert fs_record.unreported_roots((r"C:\a", r"D:\b"), (r"C:\a",)) == 1
    assert fs_record.unreported_roots((r"C:\a",), (r"C:\a", r"C:\a")) == 0
    assert fs_record.unreported_roots((r"C:\a", r"D:\b"), ()) == 2


def test_the_rejected_lookup_only_considers_the_backends_own_rejections(conn):
    run_id = running_run(conn)
    # an agent-reported issue can never be a rejection, even if its kind and seq happen to look like one
    conn.execute("INSERT INTO run_issues (run_id, source, kind, code, seq) VALUES (?, 'agent', 'rejected_record', 'x', 0)", (run_id,))
    assert not fs_ingest._seq_was_rejected(conn, run_id, 0)
    assert ingest(conn, run_id, [ok_record(n=1)]) == fs_ingest.BatchResult(1, 0, ())
    conn.execute("INSERT INTO run_issues (run_id, source, kind, code, seq) VALUES (?, 'backend', 'rejected_record', 'x', 7)", (run_id,))
    assert fs_ingest._seq_was_rejected(conn, run_id, 7) and not fs_ingest._seq_was_rejected(conn, run_id, 8)


@pytest.mark.parametrize("roots", [None, [], "C:\\app", [5], [""], [r"C:\app", 5]])
def test_runs_without_usable_explicit_roots_are_not_reconciled(conn, roots):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={} if roots is None else {"roots": roots})
    runs.start_run(conn, run_id, now=at(1))
    ingest(conn, run_id, [ok_record(n=1)])
    assert finish(conn, run_id, 1, summary=summary(1, roots=((r"Z:\whatever", "scanned"),))).status == "completed"


def test_nothing_reported_for_requested_roots_and_nothing_stored_is_failed(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": [r"C:\app"]})
    runs.start_run(conn, run_id, now=at(1))
    final = finish(conn, run_id, 0, summary=summary(0, roots=()))
    assert final.status == "failed" and final.error_summary == "no_usable_data, roots_not_scanned:1"


def test_no_summary_means_no_reconciliation_but_still_not_complete(conn):
    run_id = roots_run(conn, [r"C:\app"])
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(5), summary=None)
    assert final.status == "partial" and final.error_summary == "stop_reason_missing"


def test_reconciliation_with_the_real_scanner_and_duplicate_roots(conn, tmp_path):
    put(tmp_path, "sub/a.pem", pemgen.pem_encode(pfxgen.chain()[2]))
    roots = [str(tmp_path), str(tmp_path), str(tmp_path / "sub")]                  # duplicate and nested: Phase 1 reports overlap
    records, scan_summary = run_scan(*roots)
    assert [r["status"] for r in scan_summary["roots"]] == ["scanned", "overlap", "overlap"]
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": roots})
    runs.start_run(conn, run_id, now=at(1))
    fs_ingest.ingest_fs_batch(conn, run_id, fs_ingest.number_records(records), now=at(2))
    assert fs_ingest.finalize_fs_run(conn, run_id, now=at(3), summary=scan_summary).status == "completed"


def test_reconciliation_with_the_real_scanner_when_the_agent_drops_a_root(conn, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    put(tmp_path, "a/x.pem", pemgen.pem_encode(pfxgen.chain()[2]))
    records, scan_summary = run_scan(tmp_path / "a")                               # the agent was only given one of two roots
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": [str(tmp_path / "a"), str(other)]})
    runs.start_run(conn, run_id, now=at(1))
    fs_ingest.ingest_fs_batch(conn, run_id, fs_ingest.number_records(records), now=at(2))
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(3), summary=scan_summary)
    assert scan_summary["complete"] is True and final.status == "partial" and final.error_summary == "roots_not_scanned:1"


# =========================================================================== S3: JSON-compatible batch pairs
def observation_dump(conn, run_id):
    return [dict(r) for r in conn.execute("SELECT * FROM fs_observations WHERE run_id = ? ORDER BY seq", (run_id,))]


def strip(rows):
    return [{k: v for k, v in row.items() if k not in ("id", "run_id")} for row in rows]


def test_tuple_and_list_pairs_store_the_same_thing(conn):
    records = [ok_record(r"C:\a\1.pem", n=1), pfx_record(r"C:\a\b.pfx", n=2), pfx_record(r"C:\a\b.pfx", n=2), failure_record()]
    as_tuples, as_lists = running_run(conn), running_run(conn)
    r1 = fs_ingest.ingest_fs_batch(conn, as_tuples, [(i, rec) for i, rec in enumerate(records)], now=at(2))
    r2 = fs_ingest.ingest_fs_batch(conn, as_lists, [[i, rec] for i, rec in enumerate(records)], now=at(2))
    assert r1 == r2 == fs_ingest.BatchResult(4, 0, ())
    assert strip(observation_dump(conn, as_tuples)) == strip(observation_dump(conn, as_lists))
    assert stored_count(conn, "certificates") == 2


def test_mixed_tuple_and_list_pairs_in_one_batch(conn):
    run_id = running_run(conn)
    result = fs_ingest.ingest_fs_batch(conn, run_id, [(0, ok_record(n=1)), [1, ok_record(r"C:\a\2.pem", n=2)]], now=at(2))
    assert result.accepted == 2


def test_replay_works_across_pair_representations(conn):
    run_id = running_run(conn)
    fs_ingest.ingest_fs_batch(conn, run_id, [(0, ok_record(n=1)), (1, ok_record(r"C:\a\2.pem", n=2))], now=at(2))
    again = fs_ingest.ingest_fs_batch(conn, run_id, [[0, ok_record(n=1)], [1, ok_record(r"C:\a\2.pem", n=2)]], now=at(3))
    assert again == fs_ingest.BatchResult(0, 2, ()) and stored_count(conn) == 2


def test_a_batch_that_went_through_json_is_accepted(conn):
    run_id = running_run(conn)
    wire = json.loads(json.dumps([[i, rec] for i, rec in enumerate(
        [ok_record(n=1), pfx_record(n=2), failure_record(), ok_record(r"C:\z\é😀.pem", n=3)])]))
    assert isinstance(wire[0], list)
    assert fs_ingest.ingest_fs_batch(conn, run_id, wire, now=at(2)).accepted == 4


def test_generators_of_pairs_are_accepted(conn):
    run_id = running_run(conn)
    pairs = ([i, ok_record(rf"C:\a\{i}.pem", n=i + 1)] for i in range(3))
    assert fs_ingest.ingest_fs_batch(conn, run_id, pairs, now=at(2)).accepted == 3


@pytest.mark.parametrize("batch", [[[0]], [[0, {}, 1]], [[]], [["0", {}]], [[True, {}]], [[-1, {}]], [[2**31, {}]],
                                   [[1.5, {}]], [[None, {}]], [{"seq": 0, "record": {}}], ["ab"], [b"ab"], [{0, 1}], [(0, {}), [1]]])
def test_malformed_list_pairs_are_refused_before_anything_is_stored(conn, batch):
    run_id = running_run(conn)
    with pytest.raises(fs_ingest.BatchRejected):
        fs_ingest.ingest_fs_batch(conn, run_id, batch, now=at(2))
    assert stored_count(conn) == 0 and not conn.in_transaction


def test_one_bad_pair_discards_the_whole_batch_even_if_earlier_pairs_were_fine(conn):
    run_id = running_run(conn)
    with pytest.raises(fs_ingest.BatchRejected):
        fs_ingest.ingest_fs_batch(conn, run_id, [[0, ok_record(n=1)], [1]], now=at(2))
    assert stored_count(conn) == 0 and stored_count(conn, "certificates") == 0


# =========================================================================== validator vs database: no CHECK may be reachable
def test_validated_records_never_fail_a_database_check_exhaustive(conn):
    """Cross product over every field that appears in a CHECK constraint, including the awkward values."""
    run_id = running_run(conn)
    seq = itertools.count()
    combos = 0
    for base, fmt, chain_index, confidence, warnings, sha_suffix in itertools.product(
            (ok_record, failure_record), ("pem", "pkcs12"), (None, 0), ("high", "medium", "low"),
            ([], [WARNING], ["x" + WARNING + "x"], [WARNING + "_extra"], ["serial_not_positive"], [WARNING + "\n"]),
            ("", "\n")):
        record = base(r"C:\fuzz\f%d.pem" % combos)
        record.update(format=fmt, chain_index=chain_index, evidence_confidence=confidence, warnings=warnings)
        if base is ok_record:
            record["sha256"] = sha(7) + sha_suffix
        combos += 1
        fs_ingest.ingest_fs_batch(conn, run_id, [(next(seq), record)], now=at(2))        # must not raise
    assert combos == 2 * 2 * 2 * 3 * 6 * 2
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok" and conn.execute("PRAGMA foreign_key_check").fetchall() == []


TRICKY = ["", " ", "\n", "a\n", "\r", "\x00", "\ud800", "😀", "é", "x" * 5000, "-----BEGIN CERTIFICATE-----", "0", "-1", "٣",
          0, 1, -1, 2**31, 2**63, 10**30, 1.5, float("nan"), float("inf"), True, False, None, [], {}, [None], [[]], {"a": 1},
          b"bytes", bytearray(b"b"), (1,), "2026-02-30T00:00:00Z", "2026-03-01T12:00:00Z\n", sha(1) + "\n", WARNING,
          [WARNING], ["x" + WARNING + "x"], "PermissionError:WinError 5\n", "unknown", "high", "medium", "low"]


def test_random_field_mutations_never_raise_and_never_corrupt_the_database(conn):
    rng = random.Random(20260301)
    run_id = running_run(conn)
    bases = (lambda i: ok_record(rf"C:\r\{i}.pem", n=i % 5 + 1), lambda i: pfx_record(rf"C:\r\{i}.pfx", n=i % 5 + 1),
             lambda i: failure_record(rf"C:\r\{i}.pem"))
    fields = list(fs_record.FS_RECORD_FIELDS)
    accepted = 0
    for i in range(1500):
        record = rng.choice(bases)(i)
        for field in rng.sample(fields, 1 if rng.random() < 0.7 else rng.randint(2, 3)):
            record[field] = rng.choice(TRICKY)
        accepted += fs_ingest.ingest_fs_batch(conn, run_id, [(i, record)], now=at(2)).accepted         # must not raise
    assert accepted > 50                                                            # some mutants are still valid records
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok" and conn.execute("PRAGMA foreign_key_check").fetchall() == []
    counts = fs_ingest.derived_counts(conn, run_id)
    assert counts.records == accepted and counts.records + counts.rejected == 1500       # every record stored or cleanly rejected
