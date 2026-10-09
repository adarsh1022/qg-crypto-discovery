"""Finalization: the run's status, counts and summary come from stored evidence; the agent's claims can only add gaps."""
import pytest

from backend import fs_ingest, fs_queries, runs
from backend import run_state as rs
from ingestfx import (NOW, at, dir_error, failure_record, finish, ingest, ok_record, pfx_record, running_run, summary)


def stored(conn, run_id):
    return runs.get_run(conn, run_id)


def clean_run(conn, n=3):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(rf"C:\app\{i}.pem", n=i + 1) for i in range(n)])
    return run_id


# ------------------------------------------------------------------ 11. completed
def test_clean_full_scan_is_completed(conn):
    run_id = clean_run(conn)
    final = finish(conn, run_id, 3)
    run = stored(conn, run_id)
    assert final.status == run["status"] == "completed" and run["error_summary"] is None and run["stop_reason"] == "completed"
    assert (run["record_count"], run["finding_count"], run["rejected_count"], run["error_count"]) == (3, 3, 0, 0)
    assert run["started_at"] == "2026-03-01T12:00:01.000Z" and run["finished_at"] == "2026-03-01T12:00:10.000Z"
    assert run["duration_ms"] == 9000


def test_scan_that_found_nothing_is_still_completed(conn):
    run_id = running_run(conn)
    assert finish(conn, run_id, 0).status == "completed"


def test_scan_with_only_non_certificate_findings_and_no_gaps_is_completed(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [failure_record(r"C:\a\notcert.pem", "no_certificate", access_error=None, detail="no_certificate_block"),
                          failure_record(r"C:\a\big.pem", "too_large", access_error=None, detail="file_too_large")])
    assert finish(conn, run_id, 2).status == "completed"


def test_agent_summary_is_stored_sanitised_and_errors_become_issues(conn):
    run_id = clean_run(conn, 2)
    finish(conn, run_id, 2, summary=summary(2, roots=((r"C:\app", "scanned"),)))
    saved = stored(conn, run_id)["agent_summary"]
    assert saved["stop_reason"] == "completed" and saved["records"] == 2 and "errors" not in saved
    assert saved["roots"] == [{"root": r"C:\app", "status": "scanned"}]


# ------------------------------------------------------------------ 9/10. partial
def test_unreadable_file_makes_the_run_partial_not_failed(conn):
    run_id = clean_run(conn, 2)
    ingest(conn, run_id, [failure_record(r"C:\app\locked.pem", "access_denied")], start=2)
    final = finish(conn, run_id, 3, summary=summary(3, errors=[dir_error(r"C:\app\locked.pem", "read", "PermissionError:WinError 5")]))
    assert final.status == "partial" and final.error_summary == "file_errors:1"
    assert stored(conn, run_id)["error_count"] == 1                           # the read error is not counted twice


def test_read_error_status_also_makes_the_run_partial(conn):
    run_id = clean_run(conn, 1)
    ingest(conn, run_id, [failure_record(r"C:\app\x.pem", "read_error", detail="internal_error", access_error=None)], start=1)
    assert finish(conn, run_id, 2).status == "partial"


def test_many_file_errors_are_counted_individually(conn):
    run_id = clean_run(conn, 1)
    ingest(conn, run_id, [failure_record(rf"C:\app\l{i}.pem", "access_denied") for i in range(7)], start=1)
    final = finish(conn, run_id, 8)
    assert final.status == "partial" and final.error_summary == "file_errors:7" and final.error_count == 7


def test_directory_level_errors_make_the_run_partial(conn):
    run_id = clean_run(conn)
    final = finish(conn, run_id, 3, summary=summary(3, errors=[dir_error(kind="listdir"), dir_error(r"C:\app\x", "stat")]))
    assert final.status == "partial" and final.error_summary == "file_errors:2" and final.error_count == 2
    issues = fs_queries.list_run_issues(conn, run_id)
    assert [(i["source"], i["kind"], i["code"]) for i in issues] == [("agent", "listdir", "PermissionError:WinError 5"),
                                                                    ("agent", "stat", "PermissionError:WinError 5")]


def test_a_summary_claiming_complete_cannot_override_stored_read_errors(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), failure_record(r"C:\app\locked.pem", "access_denied")])
    lying = summary(2, stop_reason="completed", complete=True, errors=[], errors_total=0)
    assert lying["complete"] is True
    assert finish(conn, run_id, 2, summary=lying).status == "partial"


@pytest.mark.parametrize("stop_reason", ["time_limit", "entry_limit", "candidate_limit", "cancelled"])
def test_limits_and_cancellation_make_the_run_partial(conn, stop_reason):
    run_id = clean_run(conn)
    final = finish(conn, run_id, 3, summary=summary(3, stop_reason=stop_reason, roots=((r"C:\app", "partial"),)))
    assert final.status == "partial" and final.stop_reason == stop_reason and final.error_summary == f"stopped_{stop_reason}"


def test_unreached_or_unusable_roots_make_the_run_partial(conn):
    run_id = clean_run(conn)
    final = finish(conn, run_id, 3, summary=summary(3, roots=((r"C:\app", "scanned"), (r"D:\gone", "not_found"), (r"E:\x", "not_reached"))))
    assert final.status == "partial" and final.error_summary == "roots_not_scanned:2"


def test_overlapping_roots_are_not_a_coverage_gap(conn):
    run_id = clean_run(conn)
    assert finish(conn, run_id, 3, summary=summary(3, roots=((r"C:\app", "scanned"), (r"C:\app\sub", "overlap")))).status == "completed"


def test_truncated_bundles_make_the_run_partial(conn):
    run_id = clean_run(conn)
    final = finish(conn, run_id, 3, summary=summary(3, bundles_truncated=2))
    assert final.status == "partial" and final.error_summary == "bundles_truncated:2"


def test_rejected_records_make_the_run_partial(conn):
    run_id = clean_run(conn, 2)
    ingest(conn, run_id, [ok_record(n=9, key_size=0)], start=2)
    final = finish(conn, run_id, 3)
    assert final.status == "partial" and final.error_summary == "records_rejected:1"
    assert (stored(conn, run_id)["record_count"], stored(conn, run_id)["rejected_count"]) == (2, 1)


def test_lost_agent_with_stored_data_is_partial(conn):
    run_id = clean_run(conn)
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(60), outcome="lost")
    assert final.status == "partial" and final.stop_reason == "agent_lost" and final.error_summary == "agent_lost"
    assert final.record_count == 3 and stored(conn, run_id)["agent_summary"] is None


def test_multiple_gaps_are_all_reported(conn):
    run_id = clean_run(conn, 1)
    ingest(conn, run_id, [failure_record(r"C:\app\l.pem", "access_denied"), ok_record(n=9, key_size=0)], start=1)
    final = finish(conn, run_id, 3, summary=summary(3, stop_reason="time_limit", roots=((r"C:\app", "partial"), (r"D:\x", "not_found")),
                                                    bundles_truncated=1))
    assert final.status == "partial"
    assert final.error_summary == "stopped_time_limit, roots_not_scanned:1, bundles_truncated:1, file_errors:1, records_rejected:1"


# ------------------------------------------------------------------ 12. failed
def test_fatal_agent_failure_is_failed(conn):
    run_id = clean_run(conn)
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(5), outcome="failed", fatal_code="scan_crashed")
    run = stored(conn, run_id)
    assert final.status == run["status"] == "failed" and run["error_summary"] == "scan_crashed" and run["record_count"] == 3


def test_fatal_code_is_sanitised(conn):
    run_id = running_run(conn)
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(5), outcome="failed", fatal_code="C:\\Users\\bob\\secret.pfx password=x")
    assert final.error_summary == "agent_failed"


def test_nothing_scanned_and_nothing_stored_is_failed(conn):
    run_id = running_run(conn)
    final = finish(conn, run_id, 0, summary=summary(0, roots=((r"D:\gone", "not_found"),), errors=[dir_error(r"D:\gone", "root")]))
    assert final.status == "failed" and final.error_summary == "no_usable_data, roots_not_scanned:1, file_errors:1"


def test_every_record_rejected_is_failed(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [{"junk": 1}, ok_record(n=1, sha256="zz")])
    final = finish(conn, run_id, 2)
    assert final.status == "failed" and final.error_summary == "no_usable_data, records_rejected:2"


def test_lost_agent_with_no_data_is_failed(conn):
    run_id = running_run(conn)
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(60), outcome="lost")
    assert final.status == "failed" and final.error_summary == "no_usable_data, agent_lost"


def test_missing_or_unusable_summary_is_not_trusted_as_complete(conn):
    for bad in (None, "garbage", {"stop_reason": "completed"}):
        run_id = clean_run(conn)
        final = fs_ingest.finalize_fs_run(conn, run_id, now=at(5), summary=bad)
        assert final.status == "partial" and final.error_summary == "stop_reason_missing", bad
    assert [i["code"] for i in fs_queries.list_run_issues(conn, run_id)] == ["summary_invalid"]


def test_finalize_requires_a_valid_outcome(conn):
    run_id = running_run(conn)
    with pytest.raises(ValueError):
        fs_ingest.finalize_fs_run(conn, run_id, now=at(5), outcome="done")
    assert stored(conn, run_id)["status"] == "running"


# ------------------------------------------------------------------ 13. cancellation
def test_cancel_queued_run_is_failed_and_accepts_no_records(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.request_cancel(conn, run_id, now=at(2))
    assert stored(conn, run_id)["status"] == "failed"
    with pytest.raises(fs_ingest.RunNotWritable):
        ingest(conn, run_id, [ok_record(n=1)])


def test_cancel_running_run_then_agent_reports_cancelled_is_partial(conn):
    run_id = clean_run(conn)
    runs.request_cancel(conn, run_id, now=at(4))
    assert stored(conn, run_id)["cancel_requested"] is True and stored(conn, run_id)["status"] == "running"
    ingest(conn, run_id, [ok_record(r"C:\app\late.pem", n=8)], start=3)               # in-flight records are still kept
    final = finish(conn, run_id, 4, summary=summary(4, stop_reason="cancelled", roots=((r"C:\app", "partial"),)))
    assert final.status == "partial" and final.cancel_requested and final.stop_reason == "cancelled"
    assert stored(conn, run_id)["record_count"] == 4


def test_cancel_running_run_that_the_agent_still_finished_cleanly_stays_completed(conn):
    run_id = clean_run(conn)
    runs.request_cancel(conn, run_id, now=at(4))
    assert finish(conn, run_id, 3).status == "completed"                              # the cancel came too late to matter


# ------------------------------------------------------------------ 15. counts derived from stored data
def test_counts_come_from_the_database_not_the_agent_summary(conn):
    run_id = clean_run(conn, 4)
    lying = summary(4, unique_certificates=999, duplicate_observations=999, files_read=999, candidate_files=999)
    lying["records_by_status"] = {"ok": 999}
    final = finish(conn, run_id, 4, summary=lying)
    assert (final.record_count, final.finding_count, final.rejected_count, final.error_count) == (4, 4, 0, 0)
    assert final.status == "completed"


def test_summary_record_total_must_match_stored_evidence(conn):
    run_id = clean_run(conn, 3)
    final = finish(conn, run_id, 3, summary=summary(10))                              # agent claims 10 records, 3 arrived
    assert final.status == "partial" and final.error_summary == "count_mismatch"
    assert final.record_count == 3


def test_summary_claiming_fewer_records_than_stored_is_also_a_mismatch(conn):
    run_id = clean_run(conn, 3)
    assert finish(conn, run_id, 3, summary=summary(2)).error_summary == "count_mismatch"


def test_replays_and_conflicts_do_not_break_the_reconciliation(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), ok_record(n=2)])
    ingest(conn, run_id, [ok_record(n=1), ok_record(n=2)])                            # replay
    ingest(conn, run_id, [ok_record(r"C:\other.pem", n=3)])                           # seq 0 re-sent with other content
    final = finish(conn, run_id, 2)
    assert final.status == "partial" and final.error_summary == "seq_conflicts:1"     # a conflict, not also a count mismatch
    assert final.rejected_count == 0 and final.record_count == 2


def test_unlisted_agent_errors_are_a_mismatch(conn):
    run_id = clean_run(conn)
    final = finish(conn, run_id, 3, summary=summary(3, errors=[], errors_total=5))
    assert final.status == "partial" and final.error_summary == "count_mismatch"


def test_capped_error_list_is_not_a_mismatch(conn):
    run_id = clean_run(conn)
    errors = [dir_error(rf"C:\app\d{i}", "listdir") for i in range(1000)]
    final = finish(conn, run_id, 3, summary=summary(3, errors=errors, errors_total=1500))
    assert final.status == "partial" and final.error_summary == "file_errors:1000" and final.error_count == 1000


def test_unique_certificates_and_sightings_are_not_confused(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [pfx_record(n=1), pfx_record(n=1), pfx_record(n=2), ok_record(r"C:\x\a.pem", n=1)])
    final = finish(conn, run_id, 4)
    counts = fs_queries.fs_counts(conn, run_id)
    assert final.finding_count == counts.sightings == 4                              # sightings, not distinct certificates
    assert counts.unique_certificates == 2 and counts.duplicate_observations == 2
    assert final.record_count == 4


def test_counts_in_the_run_row_equal_a_fresh_recount(conn):
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1), failure_record(), ok_record(n=2, key_size=0), failure_record(r"C:\q.pem", "read_error",
                                                                                                          detail="internal_error", access_error=None)])
    final = finish(conn, run_id, 4)
    fresh = fs_ingest.derived_counts(conn, run_id)
    assert (final.record_count, final.finding_count, final.rejected_count, final.error_count) == (
        fresh.records, fresh.findings, fresh.rejected, fresh.errors) == (3, 1, 1, 2)


# ------------------------------------------------------------------ finalize guards and atomicity
def test_finalize_twice_is_refused_and_changes_nothing(conn):
    run_id = clean_run(conn)
    finish(conn, run_id, 3)
    before = dict(stored(conn, run_id))
    with pytest.raises(fs_ingest.RunNotWritable):
        finish(conn, run_id, 3, summary=summary(3, errors=[dir_error()]))
    assert stored(conn, run_id) == before and fs_queries.list_run_issues(conn, run_id) == []


def test_finalize_unknown_queued_or_wrong_type_runs_fails_safely(conn):
    with pytest.raises(runs.RunNotFound):
        finish(conn, "nope", 0)
    queued = runs.create_run(conn, "filesystem", "manual", now=NOW)
    with pytest.raises(fs_ingest.RunNotWritable):
        finish(conn, queued, 0)
    tls = running_run(conn, run_type="tls")
    with pytest.raises(runs.WrongRunType):
        finish(conn, tls, 0)
    assert not conn.in_transaction


def test_failure_while_finalizing_rolls_back_issues_and_status(conn, monkeypatch):
    run_id = clean_run(conn)
    monkeypatch.setattr(rs, "finish", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        finish(conn, run_id, 3, summary=summary(3, errors=[dir_error()]))
    assert fs_queries.list_run_issues(conn, run_id) == [] and stored(conn, run_id)["status"] == "running"
    assert not conn.in_transaction


def test_records_are_refused_after_finalization(conn):
    run_id = clean_run(conn)
    finish(conn, run_id, 3)
    with pytest.raises(fs_ingest.RunNotWritable):
        ingest(conn, run_id, [ok_record(n=9)], start=3)
    assert fs_queries.fs_counts(conn, run_id).observations == 3


def test_run_history_lists_final_statuses(conn):
    done = clean_run(conn)
    finish(conn, done, 3)
    bad = running_run(conn)
    fs_ingest.finalize_fs_run(conn, bad, now=at(5), outcome="failed")
    pending = runs.create_run(conn, "filesystem", "manual", now=NOW)
    assert [(r["run_number"], r["status"]) for r in runs.list_runs(conn)] == [(3, "queued"), (2, "failed"), (1, "completed")]
    assert pending


def test_rejected_count_counts_distinct_seqs_even_if_issue_rows_were_duplicated(conn):
    """Defence in depth: first-write-wins prevents duplicate issues, but the count must not depend on that."""
    run_id = running_run(conn)
    ingest(conn, run_id, [ok_record(n=1, key_size=0)])
    conn.execute("INSERT INTO run_issues (run_id, source, kind, code, seq) VALUES (?, 'backend', 'rejected_record', 'again', 0)", (run_id,))
    assert fs_ingest.derived_counts(conn, run_id).rejected == 1
    assert fs_queries.fs_counts(conn, run_id).rejected == 1


# ------------------------------------------------------------------ cancellation ends partial on every path
def cancel_summary(records, roots=(("C:\\app", "partial"),)):
    return summary(records, stop_reason="cancelled", roots=roots)


def test_cooperative_cancellation_with_zero_observations_is_partial(conn):
    run_id = running_run(conn)
    runs.request_cancel(conn, run_id, now=at(4))
    final = finish(conn, run_id, 0, summary=cancel_summary(0, roots=(("C:\\app", "not_reached"),)))
    assert final.status == "partial" and final.stop_reason == "cancelled" and final.record_count == 0
    assert final.error_summary == "stopped_cancelled, roots_not_scanned:1"
    assert stored(conn, run_id)["agent_summary"]["stop_reason"] == "cancelled"


def test_cooperative_cancellation_after_observations_is_partial(conn):
    run_id = clean_run(conn, 2)
    runs.request_cancel(conn, run_id, now=at(4))
    final = finish(conn, run_id, 2, summary=cancel_summary(2))
    assert final.status == "partial" and final.error_summary == "stopped_cancelled" and final.record_count == 2


def test_forced_cancellation_with_zero_observations_is_partial(conn):
    run_id = running_run(conn)
    runs.request_cancel(conn, run_id, now=at(4))
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(80), outcome="cancelled")
    assert final.status == "partial" and final.stop_reason == "cancelled" and final.record_count == 0


def test_the_three_cancellation_paths_end_the_same_way(conn):
    outcomes = []
    for path in ("cooperative", "cooperative_with_data", "forced"):
        run_id = clean_run(conn, 0 if path != "cooperative_with_data" else 2)
        runs.request_cancel(conn, run_id, now=at(4))
        if path == "forced":
            fs_ingest.finalize_fs_run(conn, run_id, now=at(80), outcome="cancelled")
        else:
            finish(conn, run_id, 0 if path == "cooperative" else 2, summary=cancel_summary(0 if path == "cooperative" else 2))
        run = stored(conn, run_id)
        outcomes.append((run["status"], run["stop_reason"], run["cancel_requested"]))
    assert outcomes == [("partial", "cancelled", True)] * 3


def test_an_agent_claiming_cancelled_without_any_cancel_request_gets_no_special_treatment(conn):
    run_id = running_run(conn)
    final = finish(conn, run_id, 0, summary=cancel_summary(0, roots=(("C:\\app", "not_reached"),)))
    assert final.status == "failed" and final.error_summary.startswith("no_usable_data")
    with_data = clean_run(conn, 1)
    assert finish(conn, with_data, 1, summary=cancel_summary(1)).status == "partial"


def test_an_ordinary_agent_failure_stays_failed_even_if_a_cancel_was_requested(conn):
    run_id = running_run(conn)
    runs.request_cancel(conn, run_id, now=at(4))
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(5), outcome="failed", fatal_code="scan_crashed")
    assert final.status == "failed" and final.error_summary == "scan_crashed"
    plain = running_run(conn)
    assert fs_ingest.finalize_fs_run(conn, plain, now=at(5), outcome="failed", fatal_code="scan_crashed").status == "failed"


def test_a_lost_agent_with_nothing_stored_is_failed_not_partial(conn):
    run_id = running_run(conn)
    assert fs_ingest.finalize_fs_run(conn, run_id, now=at(200), outcome="lost").status == "failed"


def test_nothing_scanned_without_cancellation_is_still_failed(conn):
    run_id = running_run(conn)
    final = finish(conn, run_id, 0, summary=summary(0, roots=(("D:\\gone", "not_found"),)))
    assert final.status == "failed" and final.error_summary == "no_usable_data, roots_not_scanned:1"


def test_a_cancelled_run_whose_records_were_all_rejected_is_failed(conn):
    run_id = running_run(conn)
    runs.request_cancel(conn, run_id, now=at(4))
    ingest(conn, run_id, [{"junk": 1}, {"junk": 2}])
    final = finish(conn, run_id, 2, summary=cancel_summary(2))
    assert final.status == "failed" and final.error_summary.startswith("no_usable_data")
