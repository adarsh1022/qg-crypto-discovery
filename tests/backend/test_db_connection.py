"""Connection settings, migrations, versioning, origin and transactions."""
import sqlite3

import pytest

from backend import db


# ------------------------------------------------------------------ connection settings
def test_pragmas_on_a_file_database(tmp_path):
    conn = db.connect(tmp_path / "t.db")
    try:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == db.DEFAULT_BUSY_TIMEOUT_MS
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 1          # NORMAL
        assert conn.row_factory is sqlite3.Row
        assert not conn.in_transaction                                         # autocommit: transactions are explicit
    finally:
        conn.close()


def test_busy_timeout_is_configurable(tmp_path):
    conn = db.connect(tmp_path / "t.db", busy_timeout_ms=1234)
    try:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 1234
    finally:
        conn.close()


@pytest.mark.parametrize("bad", [-1, 1.5, "5000", None, True])
def test_busy_timeout_is_validated(tmp_path, bad):
    with pytest.raises(ValueError):
        db.connect(tmp_path / "t.db", busy_timeout_ms=bad)
    assert not (tmp_path / "t.db").exists()                                    # rejected before touching disk


def test_in_memory_connection_has_foreign_keys(conn):
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_old_sqlite_is_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 36, 0))
    with pytest.raises(db.DatabaseError, match="SQLite"):
        db.connect(tmp_path / "t.db")


def test_foreign_keys_are_actually_enforced(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO run_issues (run_id, source, kind, code) VALUES ('missing-run', 'agent', 'k', 'c')")


# ------------------------------------------------------------------ migrations
def test_migrate_creates_the_schema_from_an_empty_database(conn):
    assert db.schema_version(conn) == db.latest_version() >= 1
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"meta", "runs", "certificates", "fs_observations", "tls_observations", "tls_peer_certificates",
            "nodes", "edges", "edge_runs", "schedules", "hosts", "run_issues"} <= tables
    assert db.data_origin(conn) == "agent"
    assert conn.execute("SELECT value FROM meta WHERE key = 'created_at'").fetchone() is not None


def test_migrate_is_idempotent(tmp_path):
    path = tmp_path / "t.db"
    first = db.open_database(path)
    created = first.execute("SELECT value FROM meta WHERE key = 'created_at'").fetchone()[0]
    first.close()
    second = db.open_database(path)
    try:
        assert db.schema_version(second) == db.latest_version()
        assert second.execute("SELECT value FROM meta WHERE key = 'created_at'").fetchone()[0] == created
        assert second.execute("SELECT count(*) FROM meta").fetchone()[0] == 2
    finally:
        second.close()


def test_migrations_are_contiguous_and_named():
    migrations = db._migrations()
    assert [v for v, _, _ in migrations] == list(range(1, len(migrations) + 1))
    assert migrations[0][1] == "0001_initial.sql"


def test_database_from_a_newer_version_is_refused(tmp_path):
    path = tmp_path / "t.db"
    db.open_database(path).close()
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version = {db.latest_version() + 1}")
    raw.close()
    conn = db.connect(path)
    try:
        with pytest.raises(db.SchemaVersionError):
            db.migrate(conn)
    finally:
        conn.close()
    with pytest.raises(db.SchemaVersionError):
        db.open_database(path)


def test_a_foreign_database_is_refused_and_left_untouched(tmp_path):
    path = tmp_path / "other.db"
    raw = sqlite3.connect(path)
    raw.execute("CREATE TABLE users (id INTEGER)")
    raw.commit()
    raw.close()
    with pytest.raises(db.DatabaseError, match="not created by this software"):
        db.open_database(path)
    raw = sqlite3.connect(path)
    try:
        assert [r[0] for r in raw.execute("SELECT name FROM sqlite_master")] == ["users"]
    finally:
        raw.close()


def test_failed_migration_rolls_back_completely(monkeypatch, tmp_path):
    folder = tmp_path / "migrations"
    folder.mkdir()
    (folder / "0001_bad.sql").write_text("CREATE TABLE ok_table (a TEXT);\nCREATE TABLE ok_table (b TEXT);\n")
    monkeypatch.setattr(db, "MIGRATIONS_DIR", folder)
    conn = db.connect(":memory:")
    try:
        with pytest.raises(db.DatabaseError, match="0001_bad.sql"):
            db.migrate(conn)
        assert db.schema_version(conn) == 0
        assert conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0
        assert not conn.in_transaction
    finally:
        conn.close()


def test_incremental_upgrade_applies_only_new_migrations(monkeypatch, tmp_path):
    folder = tmp_path / "migrations"
    folder.mkdir()
    (folder / "0001_first.sql").write_text("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;\n")
    monkeypatch.setattr(db, "MIGRATIONS_DIR", folder)
    conn = db.connect(":memory:")
    try:
        assert db.migrate(conn) == 1
        (folder / "0002_second.sql").write_text("CREATE TABLE extra (a INTEGER) STRICT;\n")
        assert db.migrate(conn) == 2
        assert conn.execute("SELECT count(*) FROM extra").fetchone()[0] == 0
    finally:
        conn.close()


@pytest.mark.parametrize("names", [["0002_gap.sql"], ["0001_a.sql", "0003_c.sql"], ["001_short.sql"], ["notes.sql"]])
def test_bad_migration_layout_is_refused(monkeypatch, tmp_path, names):
    folder = tmp_path / "migrations"
    folder.mkdir()
    for name in names:
        (folder / name).write_text("SELECT 1;\n")
    monkeypatch.setattr(db, "MIGRATIONS_DIR", folder)
    with pytest.raises(db.DatabaseError):
        db.latest_version()


# ------------------------------------------------------------------ origin
def test_origin_is_fixed_at_creation(tmp_path):
    path = tmp_path / "sample.db"
    db.open_database(path, "sample").close()
    with pytest.raises(db.OriginMismatch):
        db.open_database(path, "agent")
    again = db.open_database(path, "sample")
    try:
        assert db.data_origin(again) == "sample"
    finally:
        again.close()


def test_invalid_origin_is_rejected(conn):
    with pytest.raises(ValueError):
        db.migrate(conn, "real")


def test_origin_mismatch_does_not_modify_the_database(tmp_path):
    path = tmp_path / "t.db"
    db.open_database(path, "agent").close()
    with pytest.raises(db.OriginMismatch):
        db.open_database(path, "sample")
    conn = db.connect(path)
    try:
        assert db.data_origin(conn) == "agent"
    finally:
        conn.close()


# ------------------------------------------------------------------ transactions
def test_transaction_commits(conn):
    with db.transaction(conn):
        conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')")
    assert not conn.in_transaction
    assert conn.execute("SELECT value FROM meta WHERE key = 'k'").fetchone()[0] == "v"


def test_transaction_rolls_back_on_error(conn):
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')")
            raise RuntimeError("boom")
    assert not conn.in_transaction
    assert conn.execute("SELECT count(*) FROM meta WHERE key = 'k'").fetchone()[0] == 0


def test_transaction_rolls_back_on_constraint_violation(conn):
    with pytest.raises(sqlite3.IntegrityError):
        with db.transaction(conn):
            conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')")
            conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'again')")      # duplicate primary key
    assert conn.execute("SELECT count(*) FROM meta WHERE key = 'k'").fetchone()[0] == 0


def test_second_writer_waits_then_times_out_while_readers_are_not_blocked(tmp_path):
    path = tmp_path / "t.db"
    writer = db.open_database(path)
    other = db.connect(path, busy_timeout_ms=50)
    try:
        with db.transaction(writer):
            writer.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')")
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                other.execute("BEGIN IMMEDIATE")
            assert other.execute("SELECT count(*) FROM meta WHERE key = 'k'").fetchone()[0] == 0   # WAL: readers proceed
        with db.transaction(other):                                                      # free again after commit
            other.execute("INSERT INTO meta (key, value) VALUES ('k2', 'v')")
    finally:
        writer.close()
        other.close()
