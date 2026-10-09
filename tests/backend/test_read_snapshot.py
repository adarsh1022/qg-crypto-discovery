"""Read-only connections, consistent snapshots, and guaranteed cleanup (normal exit, errors and query timeouts)."""
import sqlite3
import threading

import pytest

from backend import db, reports
import reportfx


@pytest.fixture
def populated(tmp_path):
    """A file database with a run of known size, plus helpers for a writer and a read-only reader."""
    path = tmp_path / "ro.db"
    writer = db.open_database(path)
    run_id = reportfx.load(writer, reportfx.build_records())
    yield path, writer, run_id
    writer.close()


# =========================================================================== read-only connections
def test_a_read_only_connection_reads_but_cannot_write(populated):
    path, writer, run_id = populated
    reader = db.connect(path, read_only=True)
    try:
        assert reader.execute("PRAGMA query_only").fetchone()[0] == 1
        assert reader.execute("SELECT COUNT(*) FROM fs_observations").fetchone()[0] == len(reportfx.build_records())
        for statement in ("INSERT INTO meta (key, value) VALUES ('x', 'y')", "UPDATE runs SET status = 'failed'",
                          "DELETE FROM fs_observations", "DROP TABLE certificates", "CREATE TABLE evil (a TEXT)",
                          "UPDATE fs_observations SET path = 'x'", "INSERT INTO run_issues (run_id, source, kind, code) VALUES ('r', 'agent', 'k', 'c')"):
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                reader.execute(statement)
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            reader.executescript("DELETE FROM runs;")
    finally:
        reader.close()
    assert writer.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1                  # nothing changed


def test_a_connection_that_could_not_be_made_read_only_is_refused_and_closed(populated, monkeypatch):
    path, _, _ = populated

    class IgnoresReadOnly(sqlite3.Connection):
        closed = False

        def execute(self, sql, *args):
            if sql.strip().upper() == "PRAGMA QUERY_ONLY = ON":
                return super().execute("SELECT 1")                                           # the pragma silently does nothing
            return super().execute(sql, *args)

        def close(self):
            type(self).closed = True
            super().close()
    real = sqlite3.connect
    monkeypatch.setattr(db.sqlite3, "connect", lambda *a, **k: real(*a, factory=IgnoresReadOnly, **k))
    with pytest.raises(db.DatabaseError, match="read-only"):
        db.connect(path, read_only=True)
    assert IgnoresReadOnly.closed                                                          # and nothing is leaked


def test_a_rollback_that_fails_neither_masks_the_result_nor_leaves_the_snapshot_open(populated):
    path, _, run_id = populated

    class FailingRollback(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql == "ROLLBACK":
                super().execute("ROLLBACK")
                raise sqlite3.OperationalError("cannot rollback - no transaction is active")
            return super().execute(sql, *args)
    conn = sqlite3.connect(str(path), isolation_level=None, factory=FailingRollback)
    conn.row_factory = sqlite3.Row
    try:
        with db.read_snapshot(conn):
            total = conn.execute("SELECT COUNT(*) FROM fs_observations").fetchone()[0]
        assert total > 0 and not conn.in_transaction                                       # the failing rollback was absorbed
        with pytest.raises(ValueError, match="the real error"):
            with db.read_snapshot(conn):
                raise ValueError("the real error")                                         # ... and does not replace the real error
        assert not conn.in_transaction
    finally:
        conn.close()


def test_an_ordinary_connection_is_not_read_only(populated):
    path, writer, _ = populated
    assert writer.execute("PRAGMA query_only").fetchone()[0] == 0
    other = db.connect(path)
    try:
        assert other.execute("PRAGMA query_only").fetchone()[0] == 0
    finally:
        other.close()


def test_a_read_only_connection_keeps_the_other_settings(populated):
    path, _, _ = populated
    reader = db.connect(path, read_only=True)
    try:
        assert reader.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert reader.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert reader.row_factory is sqlite3.Row and not reader.in_transaction
    finally:
        reader.close()


def test_read_only_connections_never_block_the_writer(populated):
    path, writer, run_id = populated
    readers = [db.connect(path, read_only=True) for _ in range(3)]
    try:
        for reader in readers:
            reader.execute("BEGIN")
            reader.execute("SELECT COUNT(*) FROM fs_observations").fetchone()
        quick = db.connect(path, busy_timeout_ms=0)                                          # no waiting allowed
        try:
            with db.transaction(quick):
                quick.execute("INSERT INTO meta (key, value) VALUES ('while-readers', '1')")
        finally:
            quick.close()
    finally:
        for reader in readers:
            reader.execute("ROLLBACK")
            reader.close()


# =========================================================================== snapshots
def test_a_snapshot_is_consistent_while_a_writer_commits(populated):
    path, writer, run_id = populated
    reader = db.connect(path, read_only=True)
    try:
        with db.read_snapshot(reader):
            before = reader.execute("SELECT COUNT(*) FROM fs_observations").fetchone()[0]
            reportfx.load(writer, [reportfx.cert("C:\\late\\new.pem", 1, "C:\\late")], run_id, start=500)       # committed meanwhile
            assert writer.execute("SELECT COUNT(*) FROM fs_observations").fetchone()[0] == before + 1
            assert reader.execute("SELECT COUNT(*) FROM fs_observations").fetchone()[0] == before          # the snapshot does not move
        with db.read_snapshot(reader):
            assert reader.execute("SELECT COUNT(*) FROM fs_observations").fetchone()[0] == before + 1
    finally:
        reader.close()


def test_the_snapshot_is_taken_when_it_is_opened_not_at_the_first_report_query(populated):
    """A commit that lands right after the snapshot opens, before the block reads anything, must stay invisible."""
    path, writer, run_id = populated
    reader = db.connect(path, read_only=True)
    try:
        with db.read_snapshot(reader):
            reportfx.load(writer, [reportfx.cert("C:\\early\\x.pem", 3, "C:\\early")], run_id, start=700)
            assert reports.search_sightings(reader, run_id).total == len(reportfx.build_records())
        with db.read_snapshot(reader):
            assert reports.search_sightings(reader, run_id).total == len(reportfx.build_records()) + 1
    finally:
        reader.close()


def test_report_page_and_total_share_one_snapshot_even_if_a_write_lands_between_them(populated):
    path, writer, run_id = populated
    reader = db.connect(path, read_only=True)
    expected_total = len(reportfx.build_records())
    fired = []

    def intrude(statement):
        if "COUNT(*)" in statement and not fired:                                           # the total is about to run ...
            fired.append(1)
            reportfx.load(writer, [reportfx.cert("C:\\late\\x.pem", 2, "C:\\late")], run_id, start=900)   # ... a row is committed
    try:
        with db.read_snapshot(reader):
            reader.set_trace_callback(intrude)
            page = reports.search_sightings(reader, run_id, reports.SightingQuery(limit=500))
            reader.set_trace_callback(None)
        assert fired and page.total == len(page.items) == expected_total                    # page and total agree: the late row is in neither
        with db.read_snapshot(reader):
            assert reports.search_sightings(reader, run_id).total == expected_total + 1
    finally:
        reader.close()


def test_a_snapshot_always_ends_with_no_open_transaction(populated):
    path, _, _ = populated
    reader = db.connect(path, read_only=True)
    try:
        with db.read_snapshot(reader):
            assert reader.in_transaction
        assert not reader.in_transaction
        with pytest.raises(RuntimeError):
            with db.read_snapshot(reader):
                raise RuntimeError("boom")
        assert not reader.in_transaction
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            with db.read_snapshot(reader):
                reader.execute("SELECT * FROM nonexistent")
        assert not reader.in_transaction and reader.execute("SELECT 1").fetchone()[0] == 1
    finally:
        reader.close()


def test_snapshots_cannot_be_nested_or_opened_inside_a_write(populated):
    path, writer, _ = populated
    reader = db.connect(path, read_only=True)
    try:
        with db.read_snapshot(reader):
            with pytest.raises(db.DatabaseError, match="another transaction"):
                with db.read_snapshot(reader):
                    pass
            assert reader.in_transaction                                                   # the outer snapshot is intact
        assert not reader.in_transaction
    finally:
        reader.close()
    with db.transaction(writer):
        with pytest.raises(db.DatabaseError, match="another transaction"):
            with db.read_snapshot(writer):
                pass


def test_a_snapshot_survives_a_rollback_that_finds_nothing_to_roll_back(populated):
    path, _, _ = populated
    reader = db.connect(path, read_only=True)
    try:
        with db.read_snapshot(reader):
            reader.execute("ROLLBACK")                                                      # the block ended the transaction itself
        assert not reader.in_transaction
    finally:
        reader.close()


def test_reports_refuse_to_run_outside_a_snapshot(populated):
    path, writer, run_id = populated
    for call in (lambda c: reports.search_sightings(c, run_id), lambda c: reports.search_unique_certificates(c, run_id)):
        with pytest.raises(db.TransactionRequired):
            call(writer)


# =========================================================================== query budget
class Ticker:
    """A clock that advances by `step` every time it is read, and by hand."""

    def __init__(self, step=0.0):
        self.now, self.step, self.reads = 0.0, step, 0

    def __call__(self):
        self.reads += 1
        self.now += self.step
        return self.now


@pytest.mark.parametrize("seconds", [0, -1, float("inf"), float("nan"), True, "5", None])
def test_invalid_budgets_are_refused(seconds):
    with pytest.raises(ValueError):
        db.QueryBudget(seconds)


@pytest.mark.parametrize("every", [0, -1, 1.5, True, "10"])
def test_invalid_check_intervals_are_refused(every):
    with pytest.raises(ValueError):
        db.QueryBudget(5, check_every=every)


def test_the_budget_is_a_deadline_on_an_injected_clock():
    clock = Ticker()
    budget = db.QueryBudget(5, clock=clock)
    assert budget() == 0 and not budget.expired
    clock.now = 5.0
    assert budget() == 0                                                                   # exactly at the deadline is still fine
    clock.now = 5.001
    assert budget() == 1 and budget.expired
    clock.now = 0
    assert budget() == 1                                                                   # once expired it stays expired


def test_a_broken_clock_fails_closed():
    calls = []

    def clock():
        calls.append(1)
        if len(calls) > 1:
            raise OSError("clock failed")
        return 0.0
    budget = db.QueryBudget(5, clock=clock)
    assert budget() == 1 and budget.expired


def test_a_generous_budget_changes_nothing(populated):
    path, _, run_id = populated
    reader = db.connect(path, read_only=True)
    try:
        budget = db.QueryBudget(1000, check_every=1)
        with db.read_snapshot(reader, budget):
            assert reports.search_sightings(reader, run_id, reports.SightingQuery(limit=500)).total == len(reportfx.build_records())
        assert not budget.expired
    finally:
        reader.close()


def test_an_exhausted_budget_ends_the_request_with_a_safe_timeout(populated):
    path, writer, run_id = populated
    reader = db.connect(path, read_only=True)
    try:
        budget = db.QueryBudget(5, clock=Ticker(step=1.0), check_every=1)                  # 1 "second" per progress check
        with pytest.raises(db.QueryTimeout) as caught:
            with db.read_snapshot(reader, budget):
                reports.search_sightings(reader, run_id, reports.SightingQuery(q="host", limit=500))
        error = caught.value
        assert budget.expired and error.__cause__ is None and error.__suppress_context__
        text = str(error).lower()
        assert not any(w in text for w in ("select", "interrupted", "sqlite", "fs_observations"))
    finally:
        reader.close()


def test_cleanup_after_a_timeout_leaves_a_usable_connection_and_no_locks(populated):
    path, writer, run_id = populated
    reader = db.connect(path, read_only=True)
    try:
        budget = db.QueryBudget(3, clock=Ticker(step=1.0), check_every=1)
        with pytest.raises(db.QueryTimeout):
            with db.read_snapshot(reader, budget):
                reports.search_sightings(reader, run_id)
        assert not reader.in_transaction                                                    # the read snapshot was released
        quick = db.connect(path, busy_timeout_ms=0)                                         # a writer needs the lock at once
        try:
            with db.transaction(quick):
                quick.execute("INSERT INTO meta (key, value) VALUES ('after-timeout', '1')")
            quick.execute("PRAGMA wal_checkpoint(PASSIVE)")
        finally:
            quick.close()
        with db.read_snapshot(reader):                                                      # no stale deadline handler remains
            assert reports.search_sightings(reader, run_id, reports.SightingQuery(limit=500)).total == len(reportfx.build_records())
    finally:
        reader.close()


def test_the_budget_covers_the_whole_request_not_each_statement(populated):
    path, _, run_id = populated
    reader = db.connect(path, read_only=True)
    clock = Ticker()
    try:
        budget = db.QueryBudget(10, clock=clock, check_every=1)
        with pytest.raises(db.QueryTimeout):
            with db.read_snapshot(reader, budget):
                assert reports.search_sightings(reader, run_id).total > 0                    # fits in the budget
                clock.now = 11                                                               # the request has used it up
                reports.search_unique_certificates(reader, run_id)                          # so the next statement is cut off
    finally:
        reader.close()


def test_other_sqlite_errors_are_not_mistaken_for_a_timeout(populated):
    path, _, _ = populated
    reader = db.connect(path, read_only=True)
    try:
        budget = db.QueryBudget(1000, check_every=1)
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            with db.read_snapshot(reader, budget):
                reader.execute("SELECT * FROM nonexistent")
        assert not budget.expired and not reader.in_transaction
    finally:
        reader.close()


def test_a_timeout_only_counts_if_this_budget_fired(populated):
    path, _, _ = populated
    reader = db.connect(path, read_only=True)
    try:
        budget = db.QueryBudget(1000, check_every=1)
        with pytest.raises(sqlite3.OperationalError) as caught:
            with db.read_snapshot(reader, budget):
                reader.interrupt()                                                          # an interrupt that is not the budget's
                reader.execute("SELECT COUNT(*) FROM fs_observations").fetchone()
                raise sqlite3.OperationalError("interrupted")
        assert not isinstance(caught.value, db.QueryTimeout)
    finally:
        reader.close()


def test_a_query_that_never_finishes_by_itself_is_stopped_and_the_connection_closes(populated):
    """A deliberately explosive query (a cross join) is cut off by the real clock, then the connection is closed cleanly."""
    path, _, _ = populated
    reader = db.connect(path, read_only=True)
    budget = db.QueryBudget(0.05, check_every=100)
    with pytest.raises(db.QueryTimeout):
        with db.read_snapshot(reader, budget):
            reader.execute("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 8000000) SELECT COUNT(*) FROM n").fetchone()
    assert not reader.in_transaction
    reader.close()
    with pytest.raises(sqlite3.ProgrammingError):
        reader.execute("SELECT 1")


def test_timeout_cleanup_also_holds_when_the_connection_is_used_from_a_worker_thread(populated):
    path, _, run_id = populated
    outcome = {}

    def work():
        conn = db.connect(path, read_only=True)
        try:
            with db.read_snapshot(conn, db.QueryBudget(3, clock=Ticker(step=1.0), check_every=1)):
                reports.search_sightings(conn, run_id)
        except db.QueryTimeout:
            outcome["timeout"] = True
        finally:
            outcome["open_transaction"] = conn.in_transaction
            conn.close()
    worker = threading.Thread(target=work)
    worker.start()
    worker.join(30)
    assert outcome == {"timeout": True, "open_transaction": False}
