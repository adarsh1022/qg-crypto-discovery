"""Migration 0003 (lease, cancellation timestamp, immutable request), lease hashing, and explicit transaction ownership."""
import hashlib
import logging
import re
import sqlite3
import threading

import pytest

from backend import db, fs_ingest, fs_queries, run_state as rs, runs
from dbfixtures import LEASE_HASH, T_MS, insert, make_run, run_row
from ingestfx import NOW, at, failure_record, ok_record, running_run, summary

HEX64 = re.compile(r"[0-9a-f]{64}")


def run_columns(conn):
    return {r["name"]: r for r in conn.execute("PRAGMA table_xinfo(runs)")}


def update(conn, run_id, assignments, params=()):
    return conn.execute(f"UPDATE runs SET {assignments} WHERE run_id = ?", (*params, run_id))


def fetch(conn, run_id, column):
    return conn.execute(f"SELECT {column} FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0]


# =========================================================================== migration 0003: columns
def test_migration_0003_is_applied(conn):
    names = [name for _, name, _ in db._migrations()]
    assert names[2] == "0003_run_lease.sql" and db.schema_version(conn) == db.latest_version() >= 3


def test_new_columns_exist_are_text_and_the_table_is_still_strict(conn):
    columns = run_columns(conn)
    assert columns["lease_hash"]["type"] == "TEXT" and columns["cancel_requested_at"]["type"] == "TEXT"
    assert not columns["lease_hash"]["notnull"] and not columns["cancel_requested_at"]["notnull"]
    strict = {r["name"]: r["strict"] for r in conn.execute("PRAGMA table_list")}
    assert strict["runs"] == 1


def test_no_column_added_by_the_migration_could_hold_a_plaintext_token(conn):
    from test_db_schema import is_raw_material_name
    assert not any(is_raw_material_name(c) for c in run_columns(conn))
    assert "lease_token" not in run_columns(conn) and "token" not in run_columns(conn)


@pytest.mark.parametrize("bad", ["", "abc", "A" * 64, "g" * 64, "a" * 63, "a" * 65, "a" * 64 + "\n", "x" * 64])
def test_lease_hash_must_be_64_lowercase_hex(conn, bad):
    run_id = make_run(conn)
    with pytest.raises(sqlite3.IntegrityError):
        update(conn, run_id, "lease_hash = ?", (bad,))


@pytest.mark.parametrize("bad", ["2026-01-01T00:00:00Z", "yesterday", "2026-01-01 00:00:00.000", "2026-01-01T00:00:00.000Z\n"])
def test_cancel_requested_at_must_be_a_run_timestamp(conn, bad):
    run_id = make_run(conn, status="running", started_at=T_MS)
    with pytest.raises(sqlite3.IntegrityError):
        update(conn, run_id, "cancel_requested = 1, cancel_requested_at = ?", (bad,))


def test_valid_values_are_accepted(conn):
    run_id = make_run(conn, status="running", started_at=T_MS)
    update(conn, run_id, "cancel_requested = 1, cancel_requested_at = ?", (T_MS,))
    assert fetch(conn, run_id, "cancel_requested_at") == T_MS and fetch(conn, run_id, "lease_hash") == LEASE_HASH


# =========================================================================== immutable request
IMMUTABLE = [("run_id", "'other-run-id-1'"), ("run_number", "999"), ("type", "'tls'"), ("run_trigger", "'scheduled'"),
             ("config_json", "'{\"changed\":true}'"), ("queued_at", "'2026-02-02T00:00:00.000Z'")]


@pytest.mark.parametrize("column, value", IMMUTABLE)
def test_the_request_cannot_be_changed_after_creation(conn, column, value):
    if column == "run_trigger":
        conn.execute("INSERT INTO schedules (schedule_id, run_type, interval_seconds, created_at) VALUES ('s1', 'filesystem', 60, 'x')")
    run_id = make_run(conn, config_json='{"roots":["C:\\\\a"]}')
    before = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        update(conn, run_id, f"{column} = {value}")
    assert tuple(conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()) == tuple(before)


def test_schedule_id_cannot_be_changed_either(conn):
    conn.execute("INSERT INTO schedules (schedule_id, run_type, interval_seconds, created_at) VALUES ('s1', 'filesystem', 60, 'x')")
    conn.execute("INSERT INTO schedules (schedule_id, run_type, interval_seconds, created_at) VALUES ('s2', 'filesystem', 60, 'x')")
    run_id = make_run(conn, run_trigger="scheduled", schedule_id="s1")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        update(conn, run_id, "schedule_id = 's2'")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        update(conn, run_id, "schedule_id = NULL")


def test_rewriting_the_same_values_is_allowed(conn):
    """The application rewrites whole rows (save_state): an UPDATE that changes none of the request fields must pass."""
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": ["C:\\a"], "max_depth": 3})
    row = conn.execute("SELECT run_id, run_number, type, run_trigger, schedule_id, config_json, queued_at FROM runs").fetchone()
    update(conn, run_id, "run_id = ?, run_number = ?, type = ?, run_trigger = ?, schedule_id = ?, config_json = ?, queued_at = ?",
           tuple(row))
    runs.start_run(conn, run_id, now=at(1))
    runs.request_cancel(conn, run_id, now=at(2))
    runs.fail_run(conn, run_id, now=at(3), code="x")
    assert runs.get_run(conn, run_id)["config"] == {"roots": ["C:\\a"], "max_depth": 3}


def test_everything_that_is_supposed_to_change_still_can(conn):
    run_id = make_run(conn, status="running", started_at=T_MS)
    update(conn, run_id, "host_id = NULL, stop_reason = 'x', record_count = 5, finding_count = 4, rejected_count = 1, "
                         "error_count = 2, error_summary = 'e', agent_summary_json = '{}', last_heartbeat_at = ?", (T_MS,))
    update(conn, run_id, "status = 'partial', finished_at = ?, duration_ms = 0", (T_MS,))
    assert fetch(conn, run_id, "status") == "partial"


# =========================================================================== lease required / fixed
def test_a_run_cannot_start_running_without_a_lease(conn):
    run_id = make_run(conn)
    with pytest.raises(sqlite3.IntegrityError, match="needs a lease"):
        update(conn, run_id, "status = 'running', started_at = ?", (T_MS,))
    assert fetch(conn, run_id, "status") == "queued"
    update(conn, run_id, "status = 'running', started_at = ?, lease_hash = ?", (T_MS, "a" * 64))
    assert fetch(conn, run_id, "status") == "running"


def test_a_running_row_cannot_be_inserted_without_a_lease(conn):
    row = run_row(status="running", started_at=T_MS)
    del row["lease_hash"]
    with pytest.raises(sqlite3.IntegrityError, match="needs a lease"):
        insert(conn, "runs", row)
    insert(conn, "runs", run_row(status="running", started_at=T_MS, lease_hash="b" * 64))


def test_the_lease_is_fixed_once_set(conn):
    run_id = make_run(conn)
    update(conn, run_id, "lease_hash = ?", ("a" * 64,))                                 # NULL -> value: allowed once
    update(conn, run_id, "lease_hash = ?", ("a" * 64,))                                 # same value: allowed (row rewrites)
    for new in ("'" + "b" * 64 + "'", "NULL"):
        with pytest.raises(sqlite3.IntegrityError, match="lease of a run is fixed"):
            update(conn, run_id, f"lease_hash = {new}")
    assert fetch(conn, run_id, "lease_hash") == "a" * 64


def test_a_finished_run_keeps_its_lease_and_cannot_be_handed_to_anyone_else(conn):
    run_id = make_run(conn, status="running", started_at=T_MS)
    update(conn, run_id, "status = 'partial', finished_at = ?, duration_ms = 0, error_summary = 'x'", (T_MS,))
    assert fetch(conn, run_id, "lease_hash") == LEASE_HASH
    with pytest.raises(sqlite3.IntegrityError):
        update(conn, run_id, "lease_hash = ?", ("d" * 64,))
    with pytest.raises(sqlite3.IntegrityError):
        update(conn, run_id, "status = 'running', finished_at = NULL, duration_ms = NULL")


def test_the_status_machine_still_comes_first_for_invalid_transitions(conn):
    run_id = make_run(conn, status="completed", started_at=T_MS, finished_at=T_MS, duration_ms=0)
    with pytest.raises(sqlite3.IntegrityError, match="invalid run status transition"):
        update(conn, run_id, "status = 'running', lease_hash = ?, finished_at = NULL, duration_ms = NULL", ("e" * 64,))


# =========================================================================== cancel flag consistency
def test_the_cancel_flag_and_its_timestamp_go_together(conn):
    run_id = make_run(conn, status="running", started_at=T_MS)
    with pytest.raises(sqlite3.IntegrityError, match="cancellation request"):
        update(conn, run_id, "cancel_requested = 1")                                    # flag without a timestamp
    with pytest.raises(sqlite3.IntegrityError, match="cancellation request"):
        update(conn, run_id, "cancel_requested_at = ?", (T_MS,))                        # timestamp without a flag
    update(conn, run_id, "cancel_requested = 1, cancel_requested_at = ?", (T_MS,))
    assert fetch(conn, run_id, "cancel_requested") == 1


def test_a_cancellation_cannot_be_withdrawn_or_re_dated(conn):
    run_id = make_run(conn, status="running", started_at=T_MS)
    update(conn, run_id, "cancel_requested = 1, cancel_requested_at = ?", (T_MS,))
    for assignments in ("cancel_requested = 0, cancel_requested_at = NULL", "cancel_requested = 0",
                        "cancel_requested_at = '2030-01-01T00:00:00.000Z'", "cancel_requested_at = NULL"):
        with pytest.raises(sqlite3.IntegrityError, match="cancellation request"):
            update(conn, run_id, assignments)
    update(conn, run_id, "cancel_requested = 1, cancel_requested_at = ?", (T_MS,))      # rewriting the same values is fine
    assert fetch(conn, run_id, "cancel_requested_at") == T_MS


def test_inserted_rows_obey_the_same_pairing_rule(conn):
    with pytest.raises(sqlite3.IntegrityError, match="set together"):
        insert(conn, "runs", run_row(cancel_requested=1))
    with pytest.raises(sqlite3.IntegrityError, match="set together"):
        insert(conn, "runs", run_row(cancel_requested_at=T_MS))
    insert(conn, "runs", run_row(status="running", started_at=T_MS, cancel_requested=1, cancel_requested_at=T_MS))


# =========================================================================== lease tokens
def test_generate_lease_gives_a_token_and_its_sha256():
    token, token_hash = runs.generate_lease()
    assert re.fullmatch(r"[0-9a-f]{32}", token) and HEX64.fullmatch(token_hash)
    assert token_hash == hashlib.sha256(token.encode("ascii")).hexdigest() == runs.hash_lease(token) and token_hash != token
    assert len({runs.generate_lease()[0] for _ in range(200)}) == 200


@pytest.mark.parametrize("presented", [None, "", "x", 5, b"bytes", "0" * 31, "0" * 33, "A" * 32, "g" * 32, " " + "a" * 31,
                                       "a" * 32 + "\n", "٠" * 32])
def test_lease_matches_refuses_anything_that_is_not_the_token(presented):
    token, token_hash = runs.generate_lease()
    assert not runs.lease_matches(token_hash, presented)
    assert runs.lease_matches(token_hash, token)


def test_the_token_pre_filter_is_fully_anchored_and_ascii():
    """The shape check runs before hashing, so malformed input never reaches the comparison."""
    assert runs._TOKEN.fullmatch("a" * 32) and runs._TOKEN.fullmatch("0123456789abcdef" * 2)
    for bad in ("a" * 32 + "\n", "\n" + "a" * 32, "a" * 31, "a" * 33, "A" * 32, "٠" * 32, ""):
        assert runs._TOKEN.fullmatch(bad) is None


def test_the_cancellation_rules_overlap_so_no_route_to_withdrawal_exists(conn):
    """Withdrawing needs the flag and the timestamp to change together; each rule alone already forbids every route."""
    run_id = make_run(conn, status="running", started_at=T_MS)
    update(conn, run_id, "cancel_requested = 1, cancel_requested_at = ?", (T_MS,))
    for assignments in ("cancel_requested = 0", "cancel_requested = 0, cancel_requested_at = NULL",
                        "cancel_requested_at = NULL", "cancel_requested = 0, cancel_requested_at = '2031-01-01T00:00:00.000Z'"):
        with pytest.raises(sqlite3.IntegrityError, match="cancellation request"):
            update(conn, run_id, assignments)
    assert fetch(conn, run_id, "cancel_requested") == 1


def test_lease_matching_edge_cases():
    token, token_hash = runs.generate_lease()
    other, other_hash = runs.generate_lease()
    assert not runs.lease_matches(token_hash, other) and not runs.lease_matches(other_hash, token)
    assert not runs.lease_matches(None, token) and not runs.lease_matches("", token)
    assert not runs.lease_matches(token_hash, token_hash)                    # the hash is not a credential
    assert not runs.lease_matches(token_hash.upper(), token)


def test_claiming_stores_only_the_hash(tmp_path):
    path = tmp_path / "lease.db"
    conn = db.open_database(path)
    try:
        run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
        token, token_hash = runs.generate_lease()
        with db.transaction(conn):
            runs.start_run_in_tx(conn, run_id, now=at(1), lease_hash=token_hash)
        assert runs.get_lease_hash(conn, run_id) == token_hash and runs.lease_matches(runs.get_lease_hash(conn, run_id), token)
        dump = "\n".join(conn.iterdump())
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    raw = b"".join(open(str(path) + suffix, "rb").read() for suffix in ("", "-wal") if __import__("os").path.exists(str(path) + suffix))
    assert token not in dump and token.encode() not in raw
    assert token_hash in dump and token_hash.encode() in raw


def test_the_lease_never_appears_in_any_view_of_a_run(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    token, token_hash = runs.generate_lease()
    with db.transaction(conn):
        state = runs.start_run_in_tx(conn, run_id, now=at(1), lease_hash=token_hash)
    for view in (runs.get_run(conn, run_id), runs.list_runs(conn)[0]):
        text = repr(view)
        assert "lease" not in " ".join(view) and token not in text and token_hash not in text
    assert token_hash not in repr(state) and "lease" not in " ".join(state.to_columns())


def test_public_start_run_creates_its_own_lease(conn):
    first, second = runs.create_run(conn, "filesystem", "manual", now=NOW), runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.start_run(conn, first, now=at(1))
    runs.start_run(conn, second, now=at(1))
    hashes = {runs.get_lease_hash(conn, first), runs.get_lease_hash(conn, second)}
    assert len(hashes) == 2 and all(HEX64.fullmatch(h) for h in hashes)
    explicit = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.start_run(conn, explicit, now=at(1), lease_hash="9" * 64)
    assert runs.get_lease_hash(conn, explicit) == "9" * 64


def test_a_malformed_lease_hash_is_refused_and_the_run_stays_queued(conn):
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    with pytest.raises(sqlite3.IntegrityError):
        runs.start_run(conn, run_id, now=at(1), lease_hash="not-a-hash")
    assert runs.get_run(conn, run_id)["status"] == "queued" and runs.get_lease_hash(conn, run_id) is None


def test_get_lease_hash_of_an_unknown_run(conn):
    with pytest.raises(runs.RunNotFound):
        runs.get_lease_hash(conn, "nope")


def test_nothing_in_the_claim_path_logs_anything_about_the_lease(conn, caplog):
    caplog.set_level(logging.DEBUG)
    token, token_hash = runs.generate_lease()
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    with db.transaction(conn):
        runs.start_run_in_tx(conn, run_id, now=at(1), lease_hash=token_hash)
    runs.request_cancel(conn, run_id, now=at(2))
    runs.fail_run(conn, run_id, now=at(3), code="x")
    assert token not in caplog.text and token_hash not in caplog.text and "lease" not in caplog.text.lower()


def test_only_one_of_many_simultaneous_claimers_gets_the_run(tmp_path):
    path = tmp_path / "race.db"
    setup = db.open_database(path)
    run_id = runs.create_run(setup, "filesystem", "manual", now=NOW)
    setup.close()
    barrier, outcomes, lock = threading.Barrier(12), [], threading.Lock()

    def claimer(index):
        conn = db.connect(path)
        token, token_hash = runs.generate_lease()
        try:
            barrier.wait()
            with db.transaction(conn):
                runs.start_run_in_tx(conn, run_id, now=at(1 + index * 0.001), lease_hash=token_hash)
            result = ("won", token_hash)
        except rs.InvalidTransition:
            result = ("lost", token_hash)
        finally:
            conn.close()
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=claimer, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(kind for kind, _ in outcomes) == ["lost"] * 11 + ["won"]
    winner = next(h for kind, h in outcomes if kind == "won")
    final = db.connect(path)
    try:
        assert runs.get_lease_hash(final, run_id) == winner and runs.get_run(final, run_id)["status"] == "running"
    finally:
        final.close()


# =========================================================================== explicit transaction ownership
def test_require_transaction_guard(conn):
    with pytest.raises(db.TransactionRequired):
        db.require_transaction(conn)
    with db.transaction(conn):
        db.require_transaction(conn)
    assert issubclass(db.TransactionRequired, db.DatabaseError)


def in_tx_calls(conn):
    """Every transaction-aware variant with valid arguments (used outside a transaction they must all refuse)."""
    queued = runs.create_run(conn, "filesystem", "manual", now=NOW)
    live = running_run(conn)
    return {
        "create_run_in_tx": lambda: runs.create_run_in_tx(conn, "filesystem", "manual", now=NOW),
        "start_run_in_tx": lambda: runs.start_run_in_tx(conn, queued, now=at(1), lease_hash="a" * 64),
        "request_cancel_in_tx": lambda: runs.request_cancel_in_tx(conn, live, now=at(2)),
        "fail_run_in_tx": lambda: runs.fail_run_in_tx(conn, live, now=at(2), code="x"),
        "register_host_in_tx": lambda: runs.register_host_in_tx(conn, "h", "HOST", now=NOW),
        "ingest_fs_batch_in_tx": lambda: fs_ingest.ingest_fs_batch_in_tx(conn, live, [(0, ok_record(n=1))], now=at(2)),
        "finalize_fs_run_in_tx": lambda: fs_ingest.finalize_fs_run_in_tx(conn, live, now=at(3), summary=summary(0)),
    }


@pytest.mark.parametrize("name", ["create_run_in_tx", "start_run_in_tx", "request_cancel_in_tx", "fail_run_in_tx",
                                  "register_host_in_tx", "ingest_fs_batch_in_tx", "finalize_fs_run_in_tx"])
def test_every_in_tx_variant_refuses_to_run_without_a_transaction(conn, name):
    calls = in_tx_calls(conn)
    before = [tuple(r) for r in conn.execute("SELECT * FROM runs ORDER BY run_number")]
    with pytest.raises(db.TransactionRequired):
        calls[name]()
    assert [tuple(r) for r in conn.execute("SELECT * FROM runs ORDER BY run_number")] == before
    assert conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0 and not conn.in_transaction


@pytest.mark.parametrize("name", ["create_run_in_tx", "start_run_in_tx", "request_cancel_in_tx", "fail_run_in_tx",
                                  "register_host_in_tx", "ingest_fs_batch_in_tx", "finalize_fs_run_in_tx"])
def test_every_in_tx_variant_works_inside_the_callers_transaction(conn, name):
    calls = in_tx_calls(conn)
    with db.transaction(conn):
        calls[name]()
    assert not conn.in_transaction


def test_several_steps_commit_together_when_the_caller_owns_the_transaction(conn):
    with db.transaction(conn):
        run_id = runs.create_run_in_tx(conn, "filesystem", "manual", now=NOW)
        runs.start_run_in_tx(conn, run_id, now=at(1), lease_hash="a" * 64)
        result = fs_ingest.ingest_fs_batch_in_tx(conn, run_id, [(0, ok_record(n=1)), (1, failure_record())], now=at(2))
        final = fs_ingest.finalize_fs_run_in_tx(conn, run_id, now=at(3), summary=summary(2, errors=[]))
    assert result.accepted == 2 and final.status == "partial"
    assert runs.get_run(conn, run_id)["status"] == "partial" and fs_queries.fs_counts(conn, run_id).observations == 2


def test_several_steps_roll_back_together_when_one_fails(conn):
    run_id = running_run(conn)
    ids_before = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            runs.create_run_in_tx(conn, "filesystem", "manual", now=NOW)
            fs_ingest.ingest_fs_batch_in_tx(conn, run_id, [(0, ok_record(n=1))], now=at(2))
            runs.request_cancel_in_tx(conn, run_id, now=at(3))
            raise RuntimeError("the fourth step failed")
    state = runs.get_run(conn, run_id)
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == ids_before
    assert fs_queries.fs_counts(conn, run_id).observations == 0 and state["cancel_requested"] is False and state["record_count"] == 0
    assert conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 0


def test_a_failing_step_inside_the_transaction_leaves_nothing_behind(conn):
    run_id = running_run(conn)
    with pytest.raises(rs.InvalidTransition):
        with db.transaction(conn):
            fs_ingest.ingest_fs_batch_in_tx(conn, run_id, [(0, ok_record(n=1))], now=at(2))
            runs.start_run_in_tx(conn, run_id, now=at(3), lease_hash="a" * 64)          # already running: refused
    assert fs_queries.fs_counts(conn, run_id).observations == 0


@pytest.mark.parametrize("wrapper", [
    lambda c, r: runs.create_run(c, "filesystem", "manual", now=NOW),
    lambda c, r: runs.start_run(c, r, now=at(1)),
    lambda c, r: runs.request_cancel(c, r, now=at(1)),
    lambda c, r: runs.fail_run(c, r, now=at(1), code="x"),
    lambda c, r: runs.register_host(c, "h", "HOST", now=NOW),
    lambda c, r: fs_ingest.ingest_fs_batch(c, r, [(0, ok_record(n=1))], now=at(2)),
    lambda c, r: fs_ingest.finalize_fs_run(c, r, now=at(3), summary=summary(0)),
])
def test_transaction_owning_wrappers_do_not_nest_implicitly(conn, wrapper):
    """No SAVEPOINT magic: a wrapper called inside an open transaction fails loudly and the outer transaction is intact."""
    run_id = running_run(conn)
    with db.transaction(conn):
        runs.register_host_in_tx(conn, "kept", "KEPT", now=NOW)
        with pytest.raises(sqlite3.OperationalError, match="within a transaction"):
            wrapper(conn, run_id)
        assert conn.in_transaction
    assert conn.execute("SELECT COUNT(*) FROM hosts WHERE host_id = 'kept'").fetchone()[0] == 1


def test_wrappers_and_in_tx_variants_give_the_same_results(conn):
    for label in ("start", "cancel", "fail"):
        a, b = runs.create_run(conn, "filesystem", "manual", now=NOW), runs.create_run(conn, "filesystem", "manual", now=NOW)
        if label == "start":
            wrapped = runs.start_run(conn, a, now=at(1), lease_hash="a" * 64)
            with db.transaction(conn):
                direct = runs.start_run_in_tx(conn, b, now=at(1), lease_hash="a" * 64)
        elif label == "cancel":
            wrapped, direct = runs.request_cancel(conn, a, now=at(1)), None
            with db.transaction(conn):
                direct = runs.request_cancel_in_tx(conn, b, now=at(1))
        else:
            wrapped = runs.fail_run(conn, a, now=at(1), code="same")
            with db.transaction(conn):
                direct = runs.fail_run_in_tx(conn, b, now=at(1), code="same")
        assert wrapped == direct, label


def test_malformed_input_is_refused_before_the_write_lock_is_taken(conn):
    statements = []
    run_id = running_run(conn)
    conn.set_trace_callback(statements.append)
    with pytest.raises(fs_ingest.BatchRejected):
        fs_ingest.ingest_fs_batch(conn, run_id, [[0]], now=at(2))
    with pytest.raises(ValueError):
        fs_ingest.finalize_fs_run(conn, run_id, now=at(3), outcome="done")
    with pytest.raises(ValueError):
        runs.create_run(conn, "dns", "manual", now=NOW)
    with pytest.raises(ValueError):
        runs.create_run(conn, "filesystem", "manual", now=NOW, config={"password": "x"})
    conn.set_trace_callback(None)
    assert not [s for s in statements if s.upper().startswith("BEGIN")]


def test_repeated_cancel_does_not_write_again(conn):
    run_id = running_run(conn)
    with db.transaction(conn):
        first = runs.request_cancel_in_tx(conn, run_id, now=at(5))
    stamp = fetch(conn, run_id, "cancel_requested_at")
    statements = []
    conn.set_trace_callback(statements.append)
    with db.transaction(conn):
        again = runs.request_cancel_in_tx(conn, run_id, now=at(50))
    conn.set_trace_callback(None)
    assert again == first and fetch(conn, run_id, "cancel_requested_at") == stamp == "2026-03-01T12:00:05.000Z"
    assert not [s for s in statements if s.upper().startswith("UPDATE")]


# =========================================================================== backend-forced cancellation, through 2b finalization
def cancelled_run(conn, records=2):
    run_id = running_run(conn)
    fs_ingest.ingest_fs_batch(conn, run_id, [(i, ok_record(rf"C:\a\{i}.pem", n=i + 1)) for i in range(records)], now=at(2))
    runs.request_cancel(conn, run_id, now=at(5))
    return run_id


def test_an_unanswered_cancellation_is_finalized_as_partial_cancelled(conn):
    run_id = cancelled_run(conn)
    with db.transaction(conn):
        final = fs_ingest.finalize_fs_run_in_tx(conn, run_id, now=at(70), outcome="cancelled")
    stored = runs.get_run(conn, run_id)
    assert final.status == stored["status"] == "partial" and stored["stop_reason"] == "cancelled"
    assert stored["error_summary"] == "stopped_cancelled" and stored["record_count"] == 2 and stored["agent_summary"] is None
    assert stored["cancel_requested"] is True and stored["cancel_requested_at"] == "2026-03-01T12:00:05.000Z"


def test_a_silent_cancelled_agent_is_reported_as_lost_too(conn):
    run_id = cancelled_run(conn)
    with db.transaction(conn):
        final = fs_ingest.finalize_fs_run_in_tx(conn, run_id, now=at(120), outcome="cancelled", agent_lost=True)
    assert final.status == "partial" and final.error_summary == "stopped_cancelled, agent_lost"


def test_cancelling_before_anything_was_stored_is_still_partial(conn):
    run_id = cancelled_run(conn, records=0)
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(70), outcome="cancelled")
    assert final.status == "partial" and final.record_count == 0 and final.stop_reason == "cancelled"


def test_forced_cancellation_still_reports_everything_derived_from_stored_rows(conn):
    run_id = cancelled_run(conn, records=1)
    fs_ingest.ingest_fs_batch(conn, run_id, [(0, ok_record(r"C:\other.pem", n=9)), (1, failure_record(r"C:\a\locked.pem")),
                                             (2, {"junk": 1})], now=at(6))
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(70), outcome="cancelled")
    assert final.error_summary == "stopped_cancelled, file_errors:1, records_rejected:1, seq_conflicts:1"


def test_forced_cancellation_keeps_a_summary_the_agent_managed_to_send(conn):
    run_id = cancelled_run(conn)
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(70), outcome="cancelled",
                                      summary=summary(2, stop_reason="cancelled", roots=((r"C:\app", "partial"),)))
    assert final.status == "partial" and runs.get_run(conn, run_id)["agent_summary"]["stop_reason"] == "cancelled"


def test_a_finished_run_cannot_be_finalized_again(conn):
    run_id = cancelled_run(conn)
    fs_ingest.finalize_fs_run(conn, run_id, now=at(70), outcome="cancelled")
    with pytest.raises(fs_ingest.RunNotWritable):
        fs_ingest.finalize_fs_run(conn, run_id, now=at(80), outcome="cancelled")
    with pytest.raises(fs_ingest.RunNotWritable):
        fs_ingest.ingest_fs_batch(conn, run_id, [(9, ok_record(n=9))], now=at(80))
