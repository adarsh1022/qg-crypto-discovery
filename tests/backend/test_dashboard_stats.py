"""Run statistics and the dashboard payload: selection rules, bounds, zero-filled shapes and consistency with fs_summary."""
import datetime as dt
import json

import pytest

import reportfx
from backend import db, fs_ingest, run_state as rs, runs, summaries
from backend.reports import InvalidQuery
from ingestfx import at, dir_error, summary

UTC = dt.timezone.utc
CLOCK = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)


def stats(conn, **kwargs):
    with db.read_snapshot(conn):
        return summaries.run_statistics(conn, **kwargs)


def board(conn, **kwargs):
    kwargs.setdefault("now", CLOCK)
    with db.read_snapshot(conn):
        return summaries.dashboard(conn, **kwargs)


def one_summary(conn, run_id, **kwargs):
    with db.read_snapshot(conn):
        return summaries.fs_summary(conn, run_id, now=kwargs.pop("now", CLOCK), **kwargs)


def make_fs(conn, created, finished=None, *, status="completed", records=0, trigger="manual", errors=()):
    """A filesystem run created at `created` seconds, started 1 s later, ended at `finished` (None: left running)."""
    run_id = runs.create_run(conn, "filesystem", trigger, now=at(created))
    runs.start_run(conn, run_id, now=at(created + 1))
    if records:
        reportfx.load(conn, reportfx.build_records()[:records], run_id)
    if finished is None:
        return run_id
    if status == "failed":
        fs_ingest.finalize_fs_run(conn, run_id, now=at(finished), outcome="failed", fatal_code="boom")
    else:
        fs_ingest.finalize_fs_run(conn, run_id, now=at(finished), summary=summary(records, roots=((reportfx.ROOT_C, "scanned"), (reportfx.ROOT_D, "scanned")), errors=errors))
    return run_id


def make_tls(conn, created, *, finish=False):
    run_id = runs.create_run(conn, "tls", "manual", now=at(created))
    if finish:
        runs.fail_run(conn, run_id, now=at(created + 1), code="tls_unavailable")
    return run_id


# =========================================================================== run statistics
def test_an_empty_database_has_empty_statistics(conn):
    result = stats(conn)
    assert result == {"by_type_status": [], "totals": {"runs": 0, "by_status": dict.fromkeys(rs.STATUSES, 0)}, "series": [], "series_limit": 200}


def test_counts_by_type_and_status(conn):
    make_fs(conn, 10, 20, records=3)
    make_fs(conn, 30, 40, status="failed")
    make_fs(conn, 50)                                                                   # running
    make_tls(conn, 60)                                                                  # queued
    make_tls(conn, 70, finish=True)                                                     # failed
    result = stats(conn)
    assert result["by_type_status"] == [{"type": "filesystem", "status": "completed", "count": 1},
                                        {"type": "filesystem", "status": "failed", "count": 1},
                                        {"type": "filesystem", "status": "running", "count": 1},
                                        {"type": "tls", "status": "failed", "count": 1},
                                        {"type": "tls", "status": "queued", "count": 1}]
    assert result["totals"]["runs"] == 5
    assert result["totals"]["by_status"] == {"queued": 1, "running": 1, "completed": 1, "partial": 0, "failed": 2}
    assert sum(g["count"] for g in result["by_type_status"]) == 5


def test_by_type_status_has_one_entry_per_combination_with_exact_counts(conn):
    make_fs(conn, 10, 20)
    make_fs(conn, 30, 40)
    make_tls(conn, 60)
    assert stats(conn)["by_type_status"] == [{"type": "filesystem", "status": "completed", "count": 2},
                                             {"type": "tls", "status": "queued", "count": 1}]


def test_the_type_filter_restricts_counts_and_series(conn):
    make_fs(conn, 10, 20)
    make_tls(conn, 30)
    make_fs(conn, 40, 50)
    only_fs, only_tls = stats(conn, run_type="filesystem"), stats(conn, run_type="tls")
    assert only_fs["totals"]["runs"] == 2 and {r["type"] for r in only_fs["series"]} == {"filesystem"}
    assert only_tls["totals"]["runs"] == 1 and {r["type"] for r in only_tls["series"]} == {"tls"}
    assert stats(conn, run_type=None)["totals"]["runs"] == 3


def test_the_series_is_oldest_first_and_bounded_but_counts_cover_every_run(conn):
    ids = [make_fs(conn, 10 * i, 10 * i + 5) for i in range(1, 8)]
    result = stats(conn, limit=3)
    assert [r["run_id"] for r in result["series"]] == ids[-3:]                          # the three newest, oldest of them first
    assert [r["run_number"] for r in result["series"]] == sorted(r["run_number"] for r in result["series"])
    assert result["totals"]["runs"] == 7 and result["series_limit"] == 3
    assert [r["run_id"] for r in stats(conn)["series"]] == ids


def test_series_limit_extremes(conn):
    for i in range(1, 4):
        make_fs(conn, 10 * i, 10 * i + 5)
    assert len(stats(conn, limit=1)["series"]) == 1 and stats(conn, limit=1)["series"][0]["run_number"] == 3
    assert len(stats(conn, limit=summaries.MAX_SERIES)["series"]) == 3


def test_since_is_inclusive_and_compares_whole_timestamps(conn):
    early = make_fs(conn, 10, 15)
    exact = make_fs(conn, 20, 25)
    late = make_fs(conn, 30, 35)
    stamp = rs.format_ts(at(20))
    assert [r["run_id"] for r in stats(conn, since=stamp)["series"]] == [exact, late]            # at-or-after
    assert stats(conn, since=stamp)["totals"]["runs"] == 2
    next_ms = rs.format_ts(at(20) + dt.timedelta(milliseconds=1))
    assert [r["run_id"] for r in stats(conn, since=next_ms)["series"]] == [late]
    previous_ms = rs.format_ts(at(20) - dt.timedelta(milliseconds=1))
    assert [r["run_id"] for r in stats(conn, since=previous_ms)["series"]] == [exact, late]
    assert early not in [r["run_id"] for r in stats(conn, since=stamp)["series"]]


def test_since_without_milliseconds_is_normalised_so_the_boundary_second_is_included(conn):
    boundary = make_fs(conn, 20, 25)                                                    # queued_at = ...:20.000Z
    short = rs.format_ts(at(20))[:-5] + "Z"                                             # 'YYYY-MM-DDTHH:MM:SSZ'
    assert "." not in short
    assert [r["run_id"] for r in stats(conn, since=short)["series"]] == [boundary]
    # a run queued 500 ms into that second is also at-or-after it
    half = runs.create_run(conn, "filesystem", "manual", now=at(20) + dt.timedelta(milliseconds=500))
    assert [r["run_id"] for r in stats(conn, since=short)["series"]] == [boundary, half]


def test_since_in_the_far_future_matches_nothing_and_the_far_past_everything(conn):
    make_fs(conn, 10, 15)
    assert stats(conn, since="2999-01-01T00:00:00Z")["totals"]["runs"] == 0 and stats(conn, since="2999-01-01T00:00:00Z")["series"] == []
    assert stats(conn, since="2000-01-01T00:00:00.000Z")["totals"]["runs"] == 1


def test_filters_combine(conn):
    make_fs(conn, 10, 15)
    keep = make_tls(conn, 30)
    make_tls(conn, 5 + 3600)
    result = stats(conn, run_type="tls", since=rs.format_ts(at(20)))
    assert result["totals"]["runs"] == 2 and keep in [r["run_id"] for r in result["series"]]
    assert stats(conn, run_type="tls", since=rs.format_ts(at(4000)))["totals"]["runs"] == 0


def test_series_rows_have_a_fixed_shape_with_a_boolean_cancel_flag(conn):
    run_id = make_fs(conn, 10)
    runs.request_cancel(conn, run_id, now=at(12))
    row = stats(conn)["series"][0]
    assert set(row) == {"run_id", "run_number", "type", "trigger", "status", "queued_at", "started_at", "finished_at", "duration_ms",
                        "stop_reason", "cancel_requested", "record_count", "finding_count", "rejected_count", "error_count",
                        "error_summary"}
    assert row["cancel_requested"] is True and row["trigger"] == "manual" and row["status"] == "running"
    other = make_fs(conn, 30, 35)
    assert [r for r in stats(conn)["series"] if r["run_id"] == other][0]["cancel_requested"] is False


def test_series_counters_come_from_the_run_row(conn):
    run_id = make_fs(conn, 10, 20, records=12)
    row = stats(conn)["series"][0]
    stored = conn.execute("SELECT record_count, finding_count, rejected_count, error_count FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    assert (row["record_count"], row["finding_count"], row["rejected_count"], row["error_count"]) == tuple(stored)
    assert row["record_count"] == 12 and row["duration_ms"] is not None


@pytest.mark.parametrize("kwargs,field,problem", [
    (dict(limit=0), "limit", "out_of_range"), (dict(limit=201), "limit", "out_of_range"), (dict(limit=-1), "limit", "out_of_range"),
    (dict(limit=True), "limit", "wrong_type"), (dict(limit="5"), "limit", "wrong_type"), (dict(limit=None), "limit", "wrong_type"),
    (dict(limit=1.0), "limit", "wrong_type"),
    (dict(run_type="http"), "type", "unknown_value"), (dict(run_type=""), "type", "unknown_value"), (dict(run_type="FILESYSTEM"), "type", "unknown_value"),
    (dict(run_type=5), "type", "wrong_type"), (dict(run_type=["tls"]), "type", "wrong_type"),
    (dict(since="2026-03-01"), "since", "not_a_run_timestamp"), (dict(since="2026-03-01T00:00:00"), "since", "not_a_run_timestamp"),
    (dict(since="2026-03-01T00:00:00+00:00"), "since", "not_a_run_timestamp"),
    (dict(since="2026-03-01T00:00:00Z\n"), "since", "not_a_run_timestamp"), (dict(since="2026-03-01T00:00:00.1Z"), "since", "not_a_run_timestamp"),
    (dict(since="2026-03-01T00:00:00.1234Z"), "since", "not_a_run_timestamp"), (dict(since=" 2026-03-01T00:00:00Z"), "since", "not_a_run_timestamp"),
    (dict(since="２０２６-03-01T00:00:00Z"), "since", "not_a_run_timestamp"), (dict(since="' OR 1=1 --"), "since", "not_a_run_timestamp"),
    (dict(since=""), "since", "not_a_run_timestamp"), (dict(since=20260301), "since", "wrong_type"),
    (dict(since=dt.datetime(2026, 3, 1)), "since", "wrong_type")])
def test_bad_statistics_parameters_are_refused(conn, kwargs, field, problem):
    with db.read_snapshot(conn):
        with pytest.raises(InvalidQuery) as caught:
            summaries.run_statistics(conn, **kwargs)
    assert (caught.value.field, caught.value.problem) == (field, problem)


def test_statistics_do_not_modify_anything(tmp_path):
    path = tmp_path / "ro.db"
    writer = db.open_database(path)
    make_fs(writer, 10, 20, records=5)
    reader = db.connect(path, read_only=True)
    try:
        with db.read_snapshot(reader):
            result = summaries.run_statistics(reader)
            dash = summaries.dashboard(reader, now=CLOCK)
        assert result["totals"]["runs"] == 1 and dash["summary"]["totals"]["records"] == 5
    finally:
        reader.close()
        writer.close()


# =========================================================================== dashboard
def test_an_empty_database_has_an_empty_dashboard(conn):
    result = board(conn)
    assert result == {"as_of": rs.format_ts(CLOCK), "latest_run": None, "latest_terminal_fs_run": None, "summary": None,
                      "runs_by_status": dict.fromkeys(rs.STATUSES, 0), "recent_runs": []}


def test_only_unfinished_runs_means_no_summary(conn):
    queued = runs.create_run(conn, "filesystem", "manual", now=at(1))
    running = make_fs(conn, 10)
    result = board(conn)
    assert result["latest_run"]["run_id"] == running and result["latest_terminal_fs_run"] is None and result["summary"] is None
    assert result["runs_by_status"] == {"queued": 1, "running": 1, "completed": 0, "partial": 0, "failed": 0}
    assert queued in [r["run_id"] for r in result["recent_runs"]]


def test_the_latest_terminal_run_is_the_one_that_finished_last_not_the_one_created_last(conn):
    slow = make_fs(conn, 10, 100, records=4)                                            # created first, finished last
    fast = make_fs(conn, 20, 30, records=6)                                             # created later, finished earlier
    result = board(conn)
    assert result["latest_run"]["run_id"] == fast                                       # highest run_number
    assert result["latest_terminal_fs_run"]["run_id"] == slow
    assert result["summary"]["run"]["run_id"] == slow and result["summary"]["totals"]["records"] == 4


def test_a_finished_at_tie_goes_to_the_higher_run_number(conn):
    first = make_fs(conn, 10, 50, records=3)
    second = make_fs(conn, 20, 50, records=5)
    assert conn.execute("SELECT finished_at FROM runs WHERE run_id = ?", (first,)).fetchone()[0] == \
        conn.execute("SELECT finished_at FROM runs WHERE run_id = ?", (second,)).fetchone()[0]
    assert board(conn)["latest_terminal_fs_run"]["run_id"] == second


def test_tls_and_unfinished_runs_never_become_the_summarised_run(conn):
    done = make_fs(conn, 10, 20, records=3)
    make_tls(conn, 30, finish=True)                                                     # a newer, finished TLS run
    make_fs(conn, 40)                                                                   # a newer, still-running filesystem run
    runs.create_run(conn, "filesystem", "manual", now=at(50))                           # a queued one
    result = board(conn)
    assert result["latest_terminal_fs_run"]["run_id"] == done and result["summary"]["run"]["run_id"] == done
    assert result["latest_run"]["type"] == "filesystem" and result["latest_run"]["status"] == "queued"


def test_a_failed_filesystem_run_can_be_the_summarised_run(conn):
    make_fs(conn, 10, 20, records=3)
    failed = make_fs(conn, 30, 40, status="failed", records=2)
    result = board(conn)
    assert result["latest_terminal_fs_run"]["run_id"] == failed and result["latest_terminal_fs_run"]["status"] == "failed"
    assert result["summary"]["run"]["status"] == "failed" and result["summary"]["run"]["final"] is True
    assert result["summary"]["totals"]["records"] == 2                                   # nothing is substituted for the newest scan


def test_a_partial_filesystem_run_is_eligible_too(conn):
    make_fs(conn, 10, 20, records=3)
    partial = make_fs(conn, 30, 40, records=2, errors=[dir_error(r"C:\certs\private", "listdir")])
    result = board(conn)
    assert result["latest_terminal_fs_run"]["run_id"] == partial and result["latest_terminal_fs_run"]["status"] == "partial"
    assert result["summary"]["run"]["status"] == "partial" and result["summary"]["issues"]["errors"]["directory_errors"] == 1


def test_the_dashboard_summary_is_exactly_fs_summary_for_that_run(conn):
    make_fs(conn, 10, 20, records=7)
    target = make_fs(conn, 30, 90, records=20)
    make_fs(conn, 40, 50, records=1)
    for now in (CLOCK, dt.datetime(2026, 9, 1, tzinfo=UTC)):
        for top_n in (1, 5, 20):
            assert board(conn, now=now, top_n=top_n)["summary"] == one_summary(conn, target, now=now, top_n=top_n)


def test_runs_by_status_is_zero_filled_and_complete(conn):
    make_fs(conn, 10, 20)
    make_fs(conn, 30, 40, status="failed")
    make_tls(conn, 50)
    counts = board(conn)["runs_by_status"]
    assert list(counts) == list(rs.STATUSES) and counts == {"queued": 1, "running": 0, "completed": 1, "partial": 0, "failed": 1}
    assert counts == stats(conn)["totals"]["by_status"]


def test_recent_runs_are_newest_first_and_bounded(conn):
    ids = [make_fs(conn, 10 * i, 10 * i + 5) for i in range(1, 6)]
    assert [r["run_id"] for r in board(conn, recent=3)["recent_runs"]] == ids[::-1][:3]
    assert [r["run_id"] for r in board(conn)["recent_runs"]] == ids[::-1]
    assert len(board(conn, recent=1)["recent_runs"]) == 1 and board(conn, recent=1)["recent_runs"][0]["run_id"] == ids[-1]
    assert board(conn, recent=100)["runs_by_status"]["completed"] == 5


def test_latest_run_matches_the_first_recent_run_and_has_the_series_shape(conn):
    make_fs(conn, 10, 20)
    make_tls(conn, 30)
    result = board(conn)
    assert result["latest_run"] == result["recent_runs"][0] and result["latest_run"]["type"] == "tls"
    assert set(result["latest_run"]) == set(stats(conn)["series"][0])


@pytest.mark.parametrize("kwargs,field,problem", [
    (dict(now=dt.datetime(2026, 3, 1)), "now", "needs_a_timezone"), (dict(now="x"), "now", "wrong_type"),
    (dict(recent=0), "recent", "out_of_range"), (dict(recent=101), "recent", "out_of_range"), (dict(recent=True), "recent", "wrong_type"),
    (dict(recent="3"), "recent", "wrong_type"),
    (dict(top_n=0), "top_n", "out_of_range"), (dict(top_n=101), "top_n", "out_of_range"), (dict(top_n=None), "top_n", "wrong_type")])
def test_bad_dashboard_parameters_are_refused_even_with_no_runs(conn, kwargs, field, problem):
    with db.read_snapshot(conn):
        with pytest.raises(InvalidQuery) as caught:
            summaries.dashboard(conn, **{"now": CLOCK, **kwargs})
    assert (caught.value.field, caught.value.problem) == (field, problem)


def test_dashboard_numbers_come_from_one_snapshot(tmp_path):
    path = tmp_path / "snap.db"
    writer = db.open_database(path)
    done = make_fs(writer, 10, 20, records=5)
    reader = db.connect(path, read_only=True)
    fired = []

    def intrude(statement):
        if "JOIN certificates" in statement and not fired:                               # while the summary is being computed ...
            fired.append(1)
            make_fs(writer, 100, 110, records=9)                                          # ... a newer scan finishes
    try:
        with db.read_snapshot(reader):
            reader.set_trace_callback(intrude)
            result = summaries.dashboard(reader, now=CLOCK)
            reader.set_trace_callback(None)
        assert fired
        assert result["latest_terminal_fs_run"]["run_id"] == done == result["summary"]["run"]["run_id"]
        assert result["runs_by_status"]["completed"] == 1 and len(result["recent_runs"]) == 1
        with db.read_snapshot(reader):
            assert summaries.dashboard(reader, now=CLOCK)["runs_by_status"]["completed"] == 2
    finally:
        reader.close()
        writer.close()


def test_the_dashboard_payload_is_json_serialisable_and_free_of_secrets(conn):
    make_fs(conn, 10, 20, records=10)
    blob = json.dumps(board(conn))
    assert "PRIVATE KEY" not in blob and "lease" not in blob and "token" not in blob.lower()


def test_nothing_in_the_database_changes_when_reports_are_read(conn):
    make_fs(conn, 10, 20, records=10)
    before = conn.execute("PRAGMA data_version").fetchone()[0], conn.total_changes
    board(conn)
    stats(conn)
    assert (conn.execute("PRAGMA data_version").fetchone()[0], conn.total_changes) == before
