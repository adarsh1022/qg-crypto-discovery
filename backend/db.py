"""SQLite access: connections, migrations, transactions (plain sqlite3, hand-written SQL).

* connect() gives a configured connection (foreign keys on, WAL, busy timeout). Create one per
  request/thread: sqlite3 connections are not shared across threads here.
* migrate() applies backend/migrations/NNNN_*.sql in order, each inside one transaction, and records
  the version in PRAGMA user_version. A database that is newer than this code, or that is not ours,
  is refused rather than touched.
* meta.data_origin ('agent' or 'sample') is fixed when the database is created, so sample data and
  real agent evidence can never be mixed in one file.
* transaction() wraps BEGIN IMMEDIATE / COMMIT / ROLLBACK. Connections run in autocommit mode
  (isolation_level=None) so transactions are always explicit.
"""
from __future__ import annotations

import datetime as dt
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

MIN_SQLITE = (3, 37, 0)                 # STRICT tables
MIGRATIONS_DIR = Path(__file__).parent / "migrations"
ORIGINS = ("agent", "sample")
DEFAULT_BUSY_TIMEOUT_MS = 5000

_MIGRATION_NAME = re.compile(r"([0-9]{4})_[a-z0-9_]+\.sql")      # used with fullmatch


class DatabaseError(Exception):
    pass


class SchemaVersionError(DatabaseError):
    """The database was created by a newer version of this software."""


class OriginMismatch(DatabaseError):
    """The database holds a different kind of data (agent vs sample) than requested."""


def connect(path, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS) -> sqlite3.Connection:
    if sqlite3.sqlite_version_info < MIN_SQLITE:
        raise DatabaseError(f"SQLite {'.'.join(map(str, MIN_SQLITE))} or newer is required "
                            f"(found {sqlite3.sqlite_version})")
    if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int) or busy_timeout_ms < 0:
        raise ValueError("busy_timeout_ms must be a non-negative integer")
    in_memory = str(path) == ":memory:"
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=busy_timeout_ms / 1000)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")     # before the WAL switch, which can wait
        conn.execute("PRAGMA foreign_keys = ON")
        mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        conn.execute("PRAGMA synchronous = NORMAL")
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise DatabaseError("SQLite could not enable foreign key enforcement")
        if not in_memory and str(mode).lower() != "wal":
            raise DatabaseError(f"could not enable WAL journaling (got {mode!r}); use a local disk")
    except BaseException:
        conn.close()
        raise
    return conn


def _migrations() -> list[tuple[int, str, str]]:
    found = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        match = _MIGRATION_NAME.fullmatch(path.name)
        if not match:
            raise DatabaseError(f"unexpected file in migrations directory: {path.name}")
        found.append((int(match.group(1)), path.name, path.read_text(encoding="utf-8")))
    if [v for v, _, _ in found] != list(range(1, len(found) + 1)):
        raise DatabaseError("migration versions must be 1..N with no gaps")
    return found


def latest_version() -> int:
    return len(_migrations())


def schema_version(conn: sqlite3.Connection) -> int:
    return conn.execute("PRAGMA user_version").fetchone()[0]


def data_origin(conn: sqlite3.Connection) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = 'data_origin'").fetchone() \
        if _has_table(conn, "meta") else None
    return row[0] if row else None


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone() is not None


@contextmanager
def transaction(conn: sqlite3.Connection):
    """BEGIN IMMEDIATE ... COMMIT, or ROLLBACK if the block raises. Not re-entrant."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def migrate(conn: sqlite3.Connection, data_origin_: str = "agent") -> int:
    """Bring the database to the latest schema and verify its origin. Returns the schema version."""
    if data_origin_ not in ORIGINS:
        raise ValueError(f"data_origin must be one of {ORIGINS}")
    migrations = _migrations()
    current = schema_version(conn)
    if current > len(migrations):
        raise SchemaVersionError(f"database schema v{current} is newer than this software (v{len(migrations)})")
    if current == 0:
        foreign = conn.execute("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1").fetchone()
        if foreign is not None:
            raise DatabaseError("refusing to use a non-empty database that was not created by this software")
    for version, name, sql in migrations:
        if version <= current:
            continue
        try:
            # executescript() runs the script as written; the transaction is part of the script.
            conn.executescript(f"BEGIN IMMEDIATE;\n{sql}\nPRAGMA user_version = {version};\nCOMMIT;")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise DatabaseError(f"migration {name} failed") from None
    with transaction(conn):
        existing = conn.execute("SELECT value FROM meta WHERE key = 'data_origin'").fetchone()
        if existing is None:
            conn.execute("INSERT INTO meta (key, value) VALUES ('data_origin', ?)", (data_origin_,))
            conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('created_at', ?)",
                         (dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),))
        elif existing[0] != data_origin_:
            raise OriginMismatch(f"database holds {existing[0]!r} data, not {data_origin_!r}")
    return schema_version(conn)


def open_database(path, data_origin: str = "agent", *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS) -> sqlite3.Connection:
    """connect() + migrate(). The normal way to get a ready connection."""
    conn = connect(path, busy_timeout_ms=busy_timeout_ms)
    try:
        migrate(conn, data_origin)
    except BaseException:
        conn.close()
        raise
    return conn
