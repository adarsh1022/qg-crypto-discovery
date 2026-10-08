"""Run and host persistence: create, claim, cancel, fail, list, config safety, references."""
import dataclasses
import sqlite3

import pytest

from backend import db, run_state as rs, runs
from ingestfx import NOW, at


def row(conn, run_id):
    return runs.get_run(conn, run_id)


# ------------------------------------------------------------------ create
def test_create_run_is_queued_with_a_number_and_defaults(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    run = row(conn, run_id)
    assert (run["type"], run["run_trigger"], run["status"], run["run_number"]) == ("filesystem", "manual", "queued", 1)
    assert run["queued_at"] == "2026-03-01T12:00:00.000Z" and run["started_at"] is None and run["duration_ms"] is None
    assert run["config"] == {} and run["agent_summary"] is None and run["cancel_requested"] is False
    assert (run["record_count"], run["finding_count"], run["rejected_count"], run["error_count"]) == (0, 0, 0, 0)
    assert len(run_id) == 32 and int(run_id, 16) >= 0


def test_run_numbers_increase_and_ids_are_unique(conn):
    ids = [runs.create_run(conn, "filesystem", "manual", now=NOW) for _ in range(3)]
    assert len(set(ids)) == 3
    assert [row(conn, i)["run_number"] for i in ids] == [1, 2, 3]


def test_create_run_for_each_type_and_trigger(conn):
    conn.execute("INSERT INTO schedules (schedule_id, run_type, interval_seconds, created_at) VALUES ('s1', 'tls', 60, 'x')")
    for run_type in ("filesystem", "tls"):
        runs.create_run(conn, run_type, "manual", now=NOW)
    scheduled = runs.create_run(conn, "tls", "scheduled", now=NOW, schedule_id="s1")
    assert row(conn, scheduled)["run_trigger"] == "scheduled" and row(conn, scheduled)["schedule_id"] == "s1"


@pytest.mark.parametrize("run_type, trigger", [("dns", "manual"), ("filesystem", "api"), ("", "manual"), (None, "manual")])
def test_create_run_rejects_unknown_type_or_trigger(conn, run_type, trigger):
    with pytest.raises(ValueError):
        runs.create_run(conn, run_type, trigger, now=NOW)
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0


def test_manual_run_cannot_reference_a_schedule_and_unknown_schedule_fails_safely(conn):
    with pytest.raises(sqlite3.IntegrityError):
        runs.create_run(conn, "filesystem", "manual", now=NOW, schedule_id="s1")
    with pytest.raises(sqlite3.IntegrityError):
        runs.create_run(conn, "filesystem", "scheduled", now=NOW, schedule_id="missing")
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0 and not conn.in_transaction


def test_duplicate_explicit_run_id_fails_without_side_effects(conn):
    runs.create_run(conn, "filesystem", "manual", now=NOW, run_id="fixed-run-id")
    with pytest.raises(sqlite3.IntegrityError):
        runs.create_run(conn, "filesystem", "manual", now=NOW, run_id="fixed-run-id")
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1 and not conn.in_transaction


# ------------------------------------------------------------------ configuration safety
def test_config_is_stored_canonically(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": [r"C:\certs"], "max_depth": 4, "x": None})
    assert row(conn, run_id)["config"] == {"roots": [r"C:\certs"], "max_depth": 4, "x": None}


@pytest.mark.parametrize("config", [
    {"private_key": "x"}, {"pem": "x"}, {"nested": {"password": "hunter2"}}, {"list": [{"secret": 1}]}, {"raw": 1}, {"der": "x"},
    {"roots": ["-----BEGIN CERTIFICATE-----"]}, {"a": b"bytes"}, {"a": object()}, {"a": float("nan")}, {"a": float("inf")},
    {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}, {"a": "x" * 70000}, {1: "non-string key"},
])
def test_unsafe_config_is_refused_and_nothing_is_stored(conn, config):
    with pytest.raises(ValueError):
        runs.create_run(conn, "filesystem", "manual", now=NOW, config=config)
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0


@pytest.mark.parametrize("config", [[], "x", 5, ("a",)])
def test_config_must_be_an_object(conn, config):
    with pytest.raises(ValueError):
        runs.create_run(conn, "filesystem", "manual", now=NOW, config=config)


def test_config_with_legitimate_key_names_is_allowed(conn):
    runs.create_run(conn, "filesystem", "manual", now=NOW, config={"key_algorithm": "RSA", "key_size": 2048, "max_certs_per_file": 5})


def test_config_with_lone_surrogates_is_stored_as_visible_escapes(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": ["C:\\bad\ud800dir"]})
    assert row(conn, run_id)["config"] == {"roots": ["C:\\bad\\ud800dir"]}


# ------------------------------------------------------------------ start / claim
def test_start_run_moves_to_running(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    state = runs.start_run(conn, run_id, now=at(2.5))
    stored = row(conn, run_id)
    assert state.status == stored["status"] == "running"
    assert stored["started_at"] == stored["last_heartbeat_at"] == "2026-03-01T12:00:02.500Z"


def test_start_run_records_the_host(conn):
    runs.register_host(conn, "host-1", "WORKSTATION", os_name="Windows 11", agent_version="0.1", now=NOW)
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.start_run(conn, run_id, now=at(1), host_id="host-1")
    assert row(conn, run_id)["host_id"] == "host-1"


def test_start_run_with_unknown_host_fails_and_leaves_the_run_queued(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    with pytest.raises(runs.UnknownHost):
        runs.start_run(conn, run_id, now=at(1), host_id="ghost")
    assert row(conn, run_id)["status"] == "queued" and not conn.in_transaction


def test_start_run_twice_is_an_invalid_transition(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.start_run(conn, run_id, now=at(1))
    with pytest.raises(rs.InvalidTransition):
        runs.start_run(conn, run_id, now=at(2))
    assert row(conn, run_id)["started_at"] == "2026-03-01T12:00:01.000Z"          # the first claim stands


def test_two_connections_cannot_both_claim_a_run(tmp_path):
    path = tmp_path / "t.db"
    first, second = db.open_database(path), db.open_database(path)
    try:
        run_id = runs.create_run(first, "filesystem", "manual", now=NOW)
        runs.start_run(first, run_id, now=at(1))
        with pytest.raises(rs.InvalidTransition):
            runs.start_run(second, run_id, now=at(2))
    finally:
        first.close()
        second.close()


def test_unknown_run_ids_raise_run_not_found(conn):
    for call in (lambda: runs.start_run(conn, "nope", now=NOW), lambda: runs.request_cancel(conn, "nope", now=NOW),
                 lambda: runs.fail_run(conn, "nope", now=NOW, code="x"), lambda: runs.load_state(conn, "nope")):
        with pytest.raises(runs.RunNotFound):
            call()
    assert runs.get_run(conn, "nope") is None and not conn.in_transaction


# ------------------------------------------------------------------ cancel / fail
def test_cancel_queued_run_fails_it(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.request_cancel(conn, run_id, now=at(3))
    stored = row(conn, run_id)
    assert (stored["status"], stored["stop_reason"], stored["error_summary"]) == ("failed", "cancelled", "cancelled")
    assert stored["started_at"] is None and stored["duration_ms"] is None and stored["finished_at"] is not None


def test_cancel_running_run_sets_the_flag_only(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.start_run(conn, run_id, now=at(1))
    runs.request_cancel(conn, run_id, now=at(2))
    stored = row(conn, run_id)
    assert stored["status"] == "running" and stored["cancel_requested"] is True and stored["finished_at"] is None


def test_cancel_finished_run_is_refused(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.fail_run(conn, run_id, now=at(1), code="agent_not_connected")
    with pytest.raises(rs.InvalidTransition):
        runs.request_cancel(conn, run_id, now=at(2))


def test_fail_run_from_queued_and_running(conn):
    queued = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.fail_run(conn, queued, now=at(5), code="agent_not_connected")
    assert (row(conn, queued)["status"], row(conn, queued)["duration_ms"]) == ("failed", None)
    live = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.start_run(conn, live, now=at(1))
    runs.fail_run(conn, live, now=at(4), code="internal_error")
    assert (row(conn, live)["status"], row(conn, live)["duration_ms"]) == ("failed", 3000)


def test_terminal_runs_cannot_be_failed_again(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.fail_run(conn, run_id, now=at(1), code="x")
    with pytest.raises(rs.InvalidTransition):
        runs.fail_run(conn, run_id, now=at(2), code="y")
    assert row(conn, run_id)["error_summary"] == "x"


# ------------------------------------------------------------------ concurrency guard
def test_save_state_refuses_a_stale_update(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    stale = runs.load_state(conn, run_id)
    runs.start_run(conn, run_id, now=at(1))
    with pytest.raises(rs.InvalidTransition, match="changed"):
        with db.transaction(conn):
            runs.save_state(conn, run_id, rs.start(stale, at(2)), expected_status="queued")
    assert row(conn, run_id)["started_at"] == "2026-03-01T12:00:01.000Z"


# ------------------------------------------------------------------ listing
def test_list_runs_filters_orders_and_pages(conn):
    ids = [runs.create_run(conn, "filesystem" if i % 2 == 0 else "tls", "manual", now=NOW) for i in range(5)]
    runs.start_run(conn, ids[0], now=at(1))
    assert [r["run_number"] for r in runs.list_runs(conn)] == [5, 4, 3, 2, 1]                  # newest first
    assert [r["run_number"] for r in runs.list_runs(conn, run_type="tls")] == [4, 2]
    assert [r["run_number"] for r in runs.list_runs(conn, status="running")] == [1]
    assert [r["run_number"] for r in runs.list_runs(conn, run_type="filesystem", status="queued")] == [5, 3]
    assert [r["run_number"] for r in runs.list_runs(conn, limit=2, offset=1)] == [4, 3]
    assert runs.list_runs(conn, limit=0) == []


@pytest.mark.parametrize("kwargs", [dict(run_type="dns"), dict(status="paused"), dict(limit=-1), dict(offset=-1),
                                    dict(limit=True), dict(limit="5")])
def test_list_runs_validates_its_arguments(conn, kwargs):
    with pytest.raises(ValueError):
        runs.list_runs(conn, **kwargs)


def test_list_runs_uses_parameters_not_string_building(conn):
    runs.create_run(conn, "filesystem", "manual", now=NOW)
    assert runs.list_runs(conn, status="queued") != []
    with pytest.raises(ValueError):
        runs.list_runs(conn, status="queued' OR '1'='1")


# ------------------------------------------------------------------ hosts
def test_register_host_inserts_then_refreshes(conn):
    runs.register_host(conn, "h1", "ONE", os_name="Windows", agent_version="1", now=NOW)
    runs.register_host(conn, "h1", "ONE-RENAMED", os_name="Windows 11", agent_version="2", now=at(60))
    stored = dict(conn.execute("SELECT * FROM hosts WHERE host_id = 'h1'").fetchone())
    assert stored == dict(host_id="h1", hostname="ONE-RENAMED", os="Windows 11", agent_version="2",
                          first_seen_at="2026-03-01T12:00:00.000Z", last_seen_at="2026-03-01T12:01:00.000Z")
    assert conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1


@pytest.mark.parametrize("kwargs", [dict(host_id="", hostname="x"), dict(host_id="h", hostname=""),
                                    dict(host_id="h", hostname="x" * 256), dict(host_id="h", hostname="x", os_name=5),
                                    dict(host_id="h", hostname="-----BEGIN CERTIFICATE-----")])
def test_register_host_validates(conn, kwargs):
    with pytest.raises(ValueError):
        runs.register_host(conn, kwargs.pop("host_id"), kwargs.pop("hostname"), now=NOW, **kwargs)
    assert conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0


def test_hostname_with_surrogates_is_made_safe(conn):
    runs.register_host(conn, "h", "PC-\ud800", now=NOW)
    assert conn.execute("SELECT hostname FROM hosts").fetchone()[0] == "PC-\\ud800"


# ------------------------------------------------------------------ pure state is what gets stored
def test_stored_columns_equal_the_pure_states_columns(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    state = runs.start_run(conn, run_id, now=at(1))
    stored = runs.load_state(conn, run_id)
    assert stored == state and dataclasses.asdict(stored) == dataclasses.asdict(state)
