"""Finalizing a TLS run: status, counts and reasons come from stored evidence; the agent's summary can only add gaps."""
import json

import pytest

from backend import db, runs, tls_ingest
from backend import run_state as rs
from tlsingestfx import (at, failed_record, finish, ingest, peer, running_tls_run, tls_error, tls_record, tls_summary)


def state_of(conn, run):
    return runs.load_state(conn, run)


def issue_kinds(conn, run):
    return [(r["source"], r["kind"], r["code"]) for r in conn.execute("SELECT source, kind, code FROM run_issues WHERE run_id = ? ORDER BY id", (run,))]


@pytest.fixture
def run(conn):
    return running_tls_run(conn)


# ------------------------------------------------------------------ completed
def test_a_clean_scan_completes_and_counts_come_from_stored_rows(conn, run):
    ingest(conn, run, [tls_record(1), failed_record(9000), failed_record(9001, outcome="incomplete", code="connect_timeout")])
    final = finish(conn, run, summary=tls_summary(3, completed=1))
    state = state_of(conn, run)
    assert final.status == state.status == "completed" and state.error_summary is None and state.stop_reason == "completed"
    assert (state.record_count, state.finding_count, state.rejected_count, state.error_count) == (3, 1, 0, 0)
    stored = json.loads(conn.execute("SELECT agent_summary_json FROM runs WHERE run_id = ?", (run,)).fetchone()[0])
    assert stored["enumeration"] == "ok" and stored["handshakes_completed"] == 1 and "errors" not in stored


def test_a_successful_enumeration_with_no_eligible_listeners_completes_with_zero_records(conn, run):
    final = finish(conn, run, summary=tls_summary(0, listeners_found=4, targets_planned=0, targets_probed=0, policy_skipped=4))
    assert final.status == "completed" and final.record_count == 0 and final.finding_count == 0 and final.error_summary is None


def test_a_machine_with_no_listeners_at_all_also_completes(conn, run):
    assert finish(conn, run, summary=tls_summary(0, listeners_found=0, targets_planned=0)).status == "completed"


def test_findings_never_include_failed_incomplete_alert_or_unknown_probes(conn, run):
    ingest(conn, run, [failed_record(9000), failed_record(9001, outcome="incomplete", code="handshake_timeout"),
                       failed_record(9002, outcome="alert", code="x_alert"), failed_record(9003, outcome="unknown", code="unrecognised_handshake_details")])
    final = finish(conn, run, summary=tls_summary(4, completed=0))
    assert (final.status, final.record_count, final.finding_count) == ("completed", 4, 0)


def test_the_agents_claim_of_findings_cannot_inflate_the_count(conn, run):
    ingest(conn, run, [failed_record(9000)])
    final = finish(conn, run, summary=tls_summary(1, completed=1))                 # the agent CLAIMS a completed handshake
    assert final.finding_count == 0 and final.status == "partial" and "count_mismatch" in final.error_summary


# ------------------------------------------------------------------ enumeration
def test_a_failed_enumeration_with_nothing_recorded_fails_the_run(conn, run):
    summary = tls_summary(0, enumeration="failed", stop_reason="enumeration_failed", errors=[tls_error("enumerate", "table_unreadable")],
                          listeners_found=0, targets_planned=0, targets_probed=0)
    final = finish(conn, run, summary=summary)
    assert final.status == "failed" and final.record_count == 0 and final.error_count == 1
    assert final.error_summary.split(", ")[0] == "no_usable_data" and "stopped_enumeration_failed" in final.error_summary
    assert ("agent", "enumerate", "table_unreadable") in issue_kinds(conn, run)


def test_failed_and_successful_enumeration_are_distinguishable_in_the_stored_state(conn):
    ok_run, bad_run = running_tls_run(conn), running_tls_run(conn)
    finish(conn, ok_run, summary=tls_summary(0, listeners_found=0, targets_planned=0))
    finish(conn, bad_run, summary=tls_summary(0, enumeration="failed", stop_reason="enumeration_failed", errors=[tls_error("enumerate", "table_unreadable")]))
    assert (state_of(conn, ok_run).status, state_of(conn, bad_run).status) == ("completed", "failed")


def test_a_run_with_evidence_is_never_called_unusable_even_if_the_agent_says_enumeration_failed(conn, run):
    ingest(conn, run, [tls_record(1)])
    final = finish(conn, run, summary=tls_summary(1, enumeration="failed", stop_reason="enumeration_failed", errors=[tls_error("enumerate", "table_unreadable")]))
    assert final.status == "partial" and "no_usable_data" not in final.error_summary


# ------------------------------------------------------------------ partial
@pytest.mark.parametrize("stop_reason", ["time_limit", "target_limit", "cancelled"])
def test_early_stops_make_the_run_partial_and_keep_what_was_found(conn, run, stop_reason):
    ingest(conn, run, [tls_record(1)])
    final = finish(conn, run, summary=tls_summary(1, stop_reason=stop_reason))
    assert final.status == "partial" and final.record_count == 1 and f"stopped_{stop_reason}" in final.error_summary


def test_agent_errors_are_counted_and_make_the_run_partial(conn, run):
    ingest(conn, run, [tls_record(1)])
    final = finish(conn, run, summary=tls_summary(1, errors=[tls_error("probe", "target_not_local"), tls_error("probe", "probe_internal_error")]))
    assert final.status == "partial" and final.error_count == 2 and "file_errors:2" in final.error_summary
    assert issue_kinds(conn, run).count(("agent", "probe", "target_not_local")) == 1


def test_policy_skips_and_refused_probes_are_not_errors(conn, run):
    ingest(conn, run, [failed_record(9000, code="connection_refused", outcome="incomplete")])
    final = finish(conn, run, summary=tls_summary(1, completed=0, policy_skipped=5, port_filtered=3))
    assert (final.status, final.error_count, final.record_count) == ("completed", 0, 1)


def test_rejected_records_make_the_run_partial_with_a_distinct_count(conn, run):
    bad = tls_record(2)
    bad["direction"] = "inbound"
    ingest(conn, run, [tls_record(1), bad])
    final = finish(conn, run, summary=tls_summary(2, completed=1))
    assert final.status == "partial" and (final.record_count, final.rejected_count) == (1, 1) and "records_rejected:1" in final.error_summary


def test_a_sequence_conflict_makes_the_run_partial(conn, run):
    ingest(conn, run, [tls_record(1)])
    ingest(conn, run, [tls_record(1, tls_version="TLS1.2")], now=at(4))
    final = finish(conn, run, summary=tls_summary(1))
    assert final.status == "partial" and "seq_conflicts:1" in final.error_summary


def test_every_disagreement_between_the_summary_and_the_stored_evidence_is_a_count_mismatch(conn):
    cases = {
        "more records claimed": tls_summary(5, completed=1),
        "fewer records claimed": tls_summary(0, completed=0),
        "wrong completed count": tls_summary(1, completed=0),
        "errors_total disagrees": tls_summary(1, errors=[tls_error()], errors_total=7),
        "invalid error entry": tls_summary(1, errors=[{"kind": "x"}]),
        "records missing": {k: v for k, v in tls_summary(1).items() if k != "records"},
        "handshakes missing": {k: v for k, v in tls_summary(1).items() if k != "handshakes_completed"},
    }
    for label, summary in cases.items():
        run = running_tls_run(conn)
        ingest(conn, run, [tls_record(1)])
        final = finish(conn, run, summary=summary)
        assert final.status == "partial" and "count_mismatch" in final.error_summary, label


def test_an_unusable_summary_is_recorded_as_such_and_can_only_make_the_run_look_worse(conn, run):
    ingest(conn, run, [tls_record(1)])
    final = finish(conn, run, summary={"enumeration": "maybe"})
    assert final.status == "partial" and ("backend", "summary", "summary_invalid") in issue_kinds(conn, run)
    assert conn.execute("SELECT agent_summary_json FROM runs WHERE run_id = ?", (run,)).fetchone()[0] is None


# ------------------------------------------------------------------ outcomes other than 'finished'
def test_a_fatal_agent_failure_fails_the_run_with_its_code(conn, run):
    final = finish(conn, run, outcome="failed", fatal_code="invalid_config")
    assert final.status == "failed" and final.stop_reason == "invalid_config" and final.error_summary == "invalid_config"


def test_a_lost_agent_with_evidence_leaves_a_partial_run(conn, run):
    ingest(conn, run, [tls_record(1)])
    final = finish(conn, run, outcome="lost", summary=None)
    assert final.status == "partial" and final.stop_reason == "agent_lost" and final.record_count == 1 and "agent_lost" in final.error_summary


def test_a_lost_agent_with_no_evidence_fails_the_run(conn, run):
    final = finish(conn, run, outcome="lost", summary=None)
    assert final.status == "failed" and final.error_summary.startswith("no_usable_data")


def test_an_unanswered_cancellation_ends_partial_even_with_no_records(conn, run):
    with db.transaction(conn):
        runs.request_cancel_in_tx(conn, run, now=at(3))
    final = finish(conn, run, outcome="cancelled", summary=None)
    assert final.status == "partial" and final.stop_reason == "cancelled" and "stopped_cancelled" in final.error_summary


def test_a_cancelled_scan_that_stopped_cooperatively_is_partial_not_failed(conn, run):
    with db.transaction(conn):
        runs.request_cancel_in_tx(conn, run, now=at(3))
    final = finish(conn, run, summary=tls_summary(0, stop_reason="cancelled"))
    assert final.status == "partial" and "no_usable_data" not in final.error_summary


def test_a_cancel_the_backend_never_recorded_is_not_believed(conn, run):
    # Nothing was enumerated and nothing recorded: only a cancellation the BACKEND recorded turns "no usable data" into a partial run.
    claimed = tls_summary(0, enumeration="failed", stop_reason="cancelled", errors=[tls_error("enumerate", "table_unreadable")])
    final = finish(conn, run, summary=claimed)                                          # the agent says cancelled; nobody asked
    assert final.status == "failed" and "no_usable_data" in final.error_summary
    asked = running_tls_run(conn)
    with db.transaction(conn):
        runs.request_cancel_in_tx(conn, asked, now=at(3))
    assert finish(conn, asked, summary=claimed).status == "partial"


# ------------------------------------------------------------------ guards
def test_only_a_running_run_can_be_finalized_once(conn, run):
    finish(conn, run, summary=tls_summary(0))
    with pytest.raises(rs.InvalidTransition):
        finish(conn, run, summary=tls_summary(0))
    queued = runs.create_run(conn, "tls", "manual", now=at(0))
    with pytest.raises(rs.InvalidTransition):
        finish(conn, queued, summary=tls_summary(0))


def test_finalizing_the_wrong_run_type_is_refused(conn):
    from ingestfx import running_run
    with pytest.raises(runs.WrongRunType):
        finish(conn, running_run(conn), summary=tls_summary(0))


def test_a_bad_outcome_is_refused_before_anything_is_written(conn, run):
    with pytest.raises(ValueError):
        with db.transaction(conn):
            tls_ingest.finalize_tls_run_in_tx(conn, run, now=at(9), outcome="exploded")
    assert state_of(conn, run).status == "running"


def test_finalization_needs_a_caller_held_transaction(conn, run):
    with pytest.raises(Exception):
        tls_ingest.finalize_tls_run_in_tx(conn, run, now=at(9), summary=tls_summary(0))


def test_a_runs_isolated_from_another_runs_evidence(conn):
    a, b = running_tls_run(conn), running_tls_run(conn)
    ingest(conn, a, [tls_record(1), tls_record(2, port=8444)])
    ingest(conn, b, [failed_record(9000)])
    fa = finish(conn, a, summary=tls_summary(2))
    fb = finish(conn, b, summary=tls_summary(1, completed=0))
    assert (fa.record_count, fa.finding_count, fa.status) == (2, 2, "completed")
    assert (fb.record_count, fb.finding_count, fb.status) == (1, 0, "completed")
    _ = peer
