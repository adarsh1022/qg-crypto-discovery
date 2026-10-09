"""Read-side search over stored filesystem evidence: sightings and unique certificates of one run (framework-independent).

Every function takes a connection that is ALREADY inside `db.read_snapshot(...)` (it refuses to run otherwise), so the
page, the total and the frontier of one call all describe the same snapshot of the database. Nothing here writes.

Queries
  SightingQuery  one row per observation (a certificate sighting or a file that gave none), with `duplicate_kind`
  UniqueQuery    one row per distinct fingerprint in the run, with how often and where it was seen
Both are validated when constructed: unknown values, wrong types and out-of-range numbers raise InvalidQuery (a fixed
field name and problem code, never the offending value). All SQL is parameterised; sort columns come from the fixed
allowlists below and never from caller text.

Frontier (stable paging of a run that is still being written)
  The frontier is the highest `fs_observations.id` visible in a snapshot. Ids are assigned in insertion order and rows
  are never deleted, so passing a frontier back adds `id <= frontier` to EVERY observation query (page and total alike)
  and freezes the SET of observations: rows ingested later are excluded, even if their agent-assigned `seq` is lower
  than ones already seen (ingestion accepts any seq in any order). It does NOT freeze values derived from the whole
  run, which can still change when a late row arrives: `duplicate_kind`, `entry_ordinal`, and the run's issues.

Duplicate classification (mutually exclusive, reconciles with sightings - unique certificates)
  Order is by seq among the sightings visible under the frontier. A sighting is
    none          the first sighting of its fingerprint, or a record with no certificate;
    within_file   a later sighting of a fingerprint already seen at the SAME path;
    across_files  a later sighting of a fingerprint already seen only at OTHER paths.
  Summed over a run: within_file = sum over (fingerprint, path) of (n - 1); across_files = sum over fingerprints of
  (paths - 1); together they equal sightings - unique certificates, whatever the order.

Search
  `q` is a case-insensitive "contains" over path, file name, subject, issuer, serial and subject-alternative-name
  values (unique view: also the paths the certificate was seen at). Case folding is Unicode (str.casefold, via a
  registered SQL function); LIKE wildcards in the term are neutralised: '%', '_' and the escape character '\\' are
  escaped. `fingerprint` is a hex PREFIX (4-64 characters, either case). Sorting on text columns is ASCII-case-
  insensitive (SQLite NOCASE); NULLs always sort last; ties break on seq (sightings) or fingerprint (unique view).
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from . import runs
from .db import TransactionRequired
from .fs_record import CHAIN_ROLES, CONFIDENCES, FORMATS, PARSE_STATUSES, VALIDITY_STATUSES

DUPLICATE_KINDS = ("none", "within_file", "across_files")
DEFAULT_LIMIT = 100
MAX_LIMIT = 500
MAX_OFFSET = 10_000_000
MAX_FRONTIER = 2**62
MAX_SEARCH = 200
MAX_TEXT = 33000
ESCAPE = "\\"
_HEX_PREFIX = re.compile(r"[0-9a-fA-F]{4,64}")

SIGHTING_SORTS = {
    "seq": "o.seq", "path": "o.path COLLATE NOCASE", "filename": "o.filename COLLATE NOCASE",
    "scan_root": "o.scan_root COLLATE NOCASE", "format": "o.format", "discovered_at": "o.discovered_at",
    "parse_status": "o.parse_status", "validity_status": "o.validity_status", "days_to_expiry": "o.days_to_expiry",
    "evidence_confidence": "o.evidence_confidence", "subject": "c.subject COLLATE NOCASE",
    "issuer": "c.issuer COLLATE NOCASE", "key_algorithm": "c.key_algorithm", "key_size": "c.key_size",
    "signature_algorithm": "c.signature_algorithm", "not_after": "c.not_after", "duplicate_kind": "o.duplicate_kind",
}
UNIQUE_SORTS = {
    "sha256": "c.sha256", "subject": "c.subject COLLATE NOCASE", "issuer": "c.issuer COLLATE NOCASE",
    "key_algorithm": "c.key_algorithm", "key_size": "c.key_size", "signature_algorithm": "c.signature_algorithm",
    "not_after": "c.not_after", "sightings": "g.sightings", "paths": "g.paths", "first_seq": "g.first_seq",
}


class InvalidQuery(ValueError):
    """A query parameter is not acceptable. `field` and `problem` are fixed identifiers; the value is never included."""

    def __init__(self, field_name: str, problem: str):
        super().__init__(f"{field_name}: {problem}")
        self.field = field_name
        self.problem = problem


# ------------------------------------------------------------------ validation
def _choice(name: str, value: Any, allowed) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidQuery(name, "wrong_type")
    if value not in allowed:
        raise InvalidQuery(name, "unknown_value")
    return value


def _int(name: str, value: Any, low: int, high: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidQuery(name, "wrong_type")
    if not low <= value <= high:
        raise InvalidQuery(name, "out_of_range")
    return value


def _bool(name: str, value: Any) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise InvalidQuery(name, "wrong_type")
    return value


def _text(name: str, value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidQuery(name, "wrong_type")
    if not value:
        raise InvalidQuery(name, "too_short")
    if len(value) > MAX_TEXT:
        raise InvalidQuery(name, "too_long")
    return value


def _search(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidQuery("q", "wrong_type")
    if not value:
        raise InvalidQuery("q", "too_short")
    if len(value) > MAX_SEARCH:
        raise InvalidQuery("q", "too_long")
    return value


def _fingerprint(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidQuery("fingerprint", "wrong_type")
    if not _HEX_PREFIX.fullmatch(value):
        raise InvalidQuery("fingerprint", "not_a_hex_prefix_of_4_to_64_characters")
    return value.lower()


def _paging(limit: Any, offset: Any, frontier: Any, sort: Any, direction: Any, sorts: dict) -> tuple:
    if limit is None or offset is None:
        raise InvalidQuery("limit" if limit is None else "offset", "wrong_type")
    limit = _int("limit", limit, 1, MAX_LIMIT)
    offset = _int("offset", offset, 0, MAX_OFFSET)
    frontier = _int("frontier", frontier, 0, MAX_FRONTIER)
    if _choice("sort", sort, sorts) is None:
        raise InvalidQuery("sort", "wrong_type")
    if _choice("direction", direction, ("asc", "desc")) is None:
        raise InvalidQuery("direction", "wrong_type")
    return limit, offset, frontier


@dataclass(frozen=True)
class SightingQuery:
    parse_status: str | None = None
    validity_status: str | None = None
    format: str | None = None
    chain_role: str | None = None
    evidence_confidence: str | None = None
    key_algorithm: str | None = None
    key_size: int | None = None
    signature_algorithm: str | None = None
    scan_root: str | None = None
    issuer: str | None = None
    has_warnings: bool | None = None
    duplicate_kind: str | None = None
    q: str | None = None
    fingerprint: str | None = None
    sort: str = "seq"
    direction: str = "asc"
    limit: int = DEFAULT_LIMIT
    offset: int = 0
    frontier: int | None = None

    def __post_init__(self):
        for name, allowed in (("parse_status", PARSE_STATUSES), ("validity_status", VALIDITY_STATUSES), ("format", FORMATS),
                              ("chain_role", CHAIN_ROLES), ("evidence_confidence", CONFIDENCES),
                              ("duplicate_kind", DUPLICATE_KINDS)):
            _choice(name, getattr(self, name), allowed)
        for name in ("key_algorithm", "signature_algorithm", "scan_root", "issuer"):
            _text(name, getattr(self, name))
        _int("key_size", self.key_size, 1, 10**6)
        _bool("has_warnings", self.has_warnings)
        _search(self.q)
        object.__setattr__(self, "fingerprint", _fingerprint(self.fingerprint))
        _paging(self.limit, self.offset, self.frontier, self.sort, self.direction, SIGHTING_SORTS)


@dataclass(frozen=True)
class UniqueQuery:
    key_algorithm: str | None = None
    key_size: int | None = None
    signature_algorithm: str | None = None
    issuer: str | None = None
    is_ca: bool | None = None
    min_sightings: int | None = None
    q: str | None = None
    fingerprint: str | None = None
    sort: str = "sha256"
    direction: str = "asc"
    limit: int = DEFAULT_LIMIT
    offset: int = 0
    frontier: int | None = None

    def __post_init__(self):
        for name in ("key_algorithm", "signature_algorithm", "issuer"):
            _text(name, getattr(self, name))
        _int("key_size", self.key_size, 1, 10**6)
        _int("min_sightings", self.min_sightings, 1, 10**9)
        _bool("is_ca", self.is_ca)
        _search(self.q)
        object.__setattr__(self, "fingerprint", _fingerprint(self.fingerprint))
        _paging(self.limit, self.offset, self.frontier, self.sort, self.direction, UNIQUE_SORTS)


@dataclass(frozen=True)
class Page:
    items: list[dict]
    total: int               # rows matching the filters under the frontier, independent of limit / offset
    limit: int
    offset: int
    frontier: int            # the insertion-id frontier this page was cut at (pass it back for stable paging)


# ------------------------------------------------------------------ helpers
def like_escape(term: str) -> str:
    """Neutralise LIKE wildcards: the escape character first, then '%' and '_'."""
    return term.replace(ESCAPE, ESCAPE + ESCAPE).replace("%", ESCAPE + "%").replace("_", ESCAPE + "_")


def _fold(value: Any) -> Any:
    return value.casefold() if isinstance(value, str) else value


def prepare_snapshot(conn: sqlite3.Connection) -> None:
    if not conn.in_transaction:
        raise TransactionRequired("reports must run inside db.read_snapshot(), so the page and total share one snapshot")
    conn.create_function("qg_fold", 1, _fold, deterministic=True)


def require_filesystem_run(conn: sqlite3.Connection, run_id: str) -> None:
    row = conn.execute("SELECT type FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise runs.RunNotFound(run_id)
    if row["type"] != "filesystem":
        raise runs.WrongRunType("not a filesystem run")


def current_frontier(conn: sqlite3.Connection, run_id: str) -> int:
    """The highest insertion id of the run's observations in this snapshot (0 if it has none)."""
    return conn.execute("SELECT COALESCE(MAX(id), 0) FROM fs_observations WHERE run_id = ?", (run_id,)).fetchone()[0]


def _term(raw: str) -> str:
    from .safety import sanitize_text
    return "%" + like_escape(_fold(sanitize_text(raw))) + "%"                  # the same text form that is stored


def _order(sorts: dict, sort: str, direction: str, tie_break: str) -> str:
    expression = sorts[sort]
    dir_sql = "ASC" if direction == "asc" else "DESC"
    return f"({expression}) IS NULL ASC, {expression} {dir_sql}, {tie_break} ASC"        # NULLs last, then a total order


def _like(column: str, name: str = "q") -> str:
    return f"qg_fold({column}) LIKE :{name} ESCAPE '{ESCAPE}'"


# ------------------------------------------------------------------ sightings
_SIGHTING_BASE = """
WITH ranked AS (
    SELECT o.*,
           ROW_NUMBER() OVER (PARTITION BY o.sha256 ORDER BY o.seq) AS fp_rank,
           ROW_NUMBER() OVER (PARTITION BY o.sha256, o.path ORDER BY o.seq) AS fp_path_rank
    FROM fs_observations AS o
    WHERE o.run_id = :run AND o.id <= :frontier
), classified AS (
    SELECT r.*,
           CASE WHEN r.sha256 IS NULL OR r.fp_rank = 1 THEN 'none'
                WHEN r.fp_path_rank > 1 THEN 'within_file'
                ELSE 'across_files' END AS duplicate_kind
    FROM ranked AS r
)
"""
_SIGHTING_FROM = "FROM classified AS o LEFT JOIN certificates AS c ON c.sha256 = o.sha256"
_SIGHTING_SELECT = (
    "SELECT o.seq, o.entry_ordinal, o.path, o.filename, o.scan_root, o.format, o.discovered_at, o.sha256, o.chain_index, "
    "o.chain_total, o.chain_role, o.parse_status, o.detail, o.access_error, o.evidence_confidence, o.extension_mismatch, "
    "o.warnings_json, o.validity_status, o.days_to_expiry, o.not_yet_valid, o.duplicate_kind, c.serial_hex, c.subject, "
    "c.issuer, c.san_json, c.key_algorithm, c.key_size, c.key_curve, c.signature_algorithm, c.not_before, c.not_after, "
    "c.is_ca ")


def _sighting_where(query: SightingQuery, params: dict) -> str:
    clauses: list[str] = []
    for name, column in (("parse_status", "o.parse_status"), ("validity_status", "o.validity_status"), ("format", "o.format"),
                         ("chain_role", "o.chain_role"), ("evidence_confidence", "o.evidence_confidence"),
                         ("scan_root", "o.scan_root"), ("duplicate_kind", "o.duplicate_kind"),
                         ("key_algorithm", "c.key_algorithm"), ("key_size", "c.key_size"),
                         ("signature_algorithm", "c.signature_algorithm"), ("issuer", "c.issuer")):
        value = getattr(query, name)
        if value is not None:
            clauses.append(f"{column} = :{name}")
            params[name] = value
    if query.has_warnings is not None:
        clauses.append("o.warnings_json <> '[]'" if query.has_warnings else "o.warnings_json = '[]'")
    if query.fingerprint is not None:
        clauses.append("substr(o.sha256, 1, :fp_length) = :fingerprint")
        params["fp_length"], params["fingerprint"] = len(query.fingerprint), query.fingerprint
    if query.q is not None:
        params["q"] = _term(query.q)
        clauses.append("(" + " OR ".join([
            _like("o.path"), _like("o.filename"), _like("c.subject"), _like("c.issuer"), _like("c.serial_hex"),
            "EXISTS (SELECT 1 FROM json_each(c.san_json) AS s WHERE " + _like("json_extract(s.value, '$.value')") + ")"]) + ")")
    return " AND ".join(clauses) if clauses else "1 = 1"


def _sighting_item(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["warnings"] = json.loads(out.pop("warnings_json"))
    san = out.pop("san_json")
    out["san"] = None if san is None else json.loads(san)
    for flag in ("extension_mismatch", "not_yet_valid", "is_ca"):
        if out[flag] is not None:
            out[flag] = bool(out[flag])
    return out


def search_sightings(conn: sqlite3.Connection, run_id: str, query: SightingQuery | None = None) -> Page:
    """One page of the run's observations plus the total that matches the same filters under the same frontier."""
    query = query or SightingQuery()
    prepare_snapshot(conn)
    require_filesystem_run(conn, run_id)
    frontier = query.frontier if query.frontier is not None else current_frontier(conn, run_id)
    params: dict[str, Any] = {"run": run_id, "frontier": frontier}
    where = _sighting_where(query, params)                                       # ONE builder: page and total cannot drift
    total = conn.execute(f"{_SIGHTING_BASE} SELECT COUNT(*) {_SIGHTING_FROM} WHERE {where}", params).fetchone()[0]
    rows = conn.execute(
        f"{_SIGHTING_BASE} {_SIGHTING_SELECT}{_SIGHTING_FROM} WHERE {where} "
        f"ORDER BY {_order(SIGHTING_SORTS, query.sort, query.direction, 'o.seq')} LIMIT :limit OFFSET :offset",
        {**params, "limit": query.limit, "offset": query.offset}).fetchall()
    return Page([_sighting_item(r) for r in rows], total, query.limit, query.offset, frontier)


# ------------------------------------------------------------------ unique certificates
_UNIQUE_BASE = """
WITH grp AS (
    SELECT o.sha256 AS sha256, COUNT(*) AS sightings, COUNT(DISTINCT o.path) AS paths, MIN(o.seq) AS first_seq
    FROM fs_observations AS o
    WHERE o.run_id = :run AND o.id <= :frontier AND o.sha256 IS NOT NULL
    GROUP BY o.sha256
)
"""
_UNIQUE_FROM = "FROM grp AS g JOIN certificates AS c ON c.sha256 = g.sha256"
_UNIQUE_SELECT = (
    "SELECT c.sha256, c.serial_hex, c.subject, c.issuer, c.san_json, c.key_algorithm, c.key_size, c.key_curve, "
    "c.signature_algorithm, c.not_before, c.not_after, c.is_ca, g.sightings, g.paths, g.first_seq, "
    "(SELECT x.path FROM fs_observations AS x WHERE x.run_id = :run AND x.id <= :frontier AND x.sha256 = c.sha256 "
    " ORDER BY x.seq LIMIT 1) AS first_path ")


def _unique_where(query: UniqueQuery, params: dict) -> str:
    clauses: list[str] = []
    for name, column in (("key_algorithm", "c.key_algorithm"), ("key_size", "c.key_size"),
                         ("signature_algorithm", "c.signature_algorithm"), ("issuer", "c.issuer")):
        value = getattr(query, name)
        if value is not None:
            clauses.append(f"{column} = :{name}")
            params[name] = value
    if query.is_ca is not None:
        clauses.append("c.is_ca = :is_ca")
        params["is_ca"] = int(query.is_ca)
    if query.min_sightings is not None:
        clauses.append("g.sightings >= :min_sightings")
        params["min_sightings"] = query.min_sightings
    if query.fingerprint is not None:
        clauses.append("substr(c.sha256, 1, :fp_length) = :fingerprint")
        params["fp_length"], params["fingerprint"] = len(query.fingerprint), query.fingerprint
    if query.q is not None:
        params["q"] = _term(query.q)
        clauses.append("(" + " OR ".join([
            _like("c.subject"), _like("c.issuer"), _like("c.serial_hex"),
            "EXISTS (SELECT 1 FROM json_each(c.san_json) AS s WHERE " + _like("json_extract(s.value, '$.value')") + ")",
            "EXISTS (SELECT 1 FROM fs_observations AS x WHERE x.run_id = :run AND x.id <= :frontier AND x.sha256 = c.sha256 AND ("
            + _like("x.path") + " OR " + _like("x.filename") + "))"]) + ")")
    return " AND ".join(clauses) if clauses else "1 = 1"


def _unique_item(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["san"] = json.loads(out.pop("san_json"))
    out["is_ca"] = None if out["is_ca"] is None else bool(out["is_ca"])
    return out


def search_unique_certificates(conn: sqlite3.Connection, run_id: str, query: UniqueQuery | None = None) -> Page:
    """One page of the run's distinct fingerprints, each with its sighting and path counts under the frontier."""
    query = query or UniqueQuery()
    prepare_snapshot(conn)
    require_filesystem_run(conn, run_id)
    frontier = query.frontier if query.frontier is not None else current_frontier(conn, run_id)
    params: dict[str, Any] = {"run": run_id, "frontier": frontier}
    where = _unique_where(query, params)
    total = conn.execute(f"{_UNIQUE_BASE} SELECT COUNT(*) {_UNIQUE_FROM} WHERE {where}", params).fetchone()[0]
    rows = conn.execute(
        f"{_UNIQUE_BASE} {_UNIQUE_SELECT}{_UNIQUE_FROM} WHERE {where} "
        f"ORDER BY {_order(UNIQUE_SORTS, query.sort, query.direction, 'c.sha256')} LIMIT :limit OFFSET :offset",
        {**params, "limit": query.limit, "offset": query.offset}).fetchall()
    return Page([_unique_item(r) for r in rows], total, query.limit, query.offset, frontier)
