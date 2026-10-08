"""Read-side queries over stored filesystem evidence (parameterised SQL, no framework).

Two different things are counted and kept apart:
  * sightings (observations): every row of fs_observations that carries a certificate
  * unique certificates:      distinct SHA-256 values
Duplicates are derived here at query time, never stored.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from .fs_record import PARSE_STATUSES, VALIDITY_STATUSES
from .runs import _page

_OBSERVATION_SELECT = (
    "SELECT o.id, o.run_id, o.seq, o.entry_ordinal, o.path, o.filename, o.scan_root, o.format, o.discovered_at, "
    "       o.sha256, o.chain_index, o.chain_total, o.chain_role, o.parse_status, o.detail, o.access_error, "
    "       o.evidence_confidence, o.extension_mismatch, o.warnings_json, o.validity_status, o.days_to_expiry, "
    "       o.not_yet_valid, c.serial_hex, c.subject, c.issuer, c.san_json, c.key_algorithm, c.key_size, c.key_curve, "
    "       c.signature_algorithm, c.not_before, c.not_after, c.is_ca "
    "FROM fs_observations AS o LEFT JOIN certificates AS c ON c.sha256 = o.sha256 ")


@dataclass(frozen=True)
class FsCounts:
    observations: int                 # every stored record, including files that gave no certificate
    sightings: int                    # certificate sightings (parse_status ok)
    unique_certificates: int          # distinct SHA-256 among the sightings
    duplicate_observations: int       # sightings - unique_certificates
    repeats_within_file: int          # sightings of a certificate already seen earlier in the same file
    parse_failures: int               # records with a status other than ok / no_certificate / skipped
    by_parse_status: dict
    by_validity_status: dict          # as of discovery time, over sightings
    issues: int
    rejected: int                     # records refused and never stored
    seq_conflicts: int                # seqs re-sent with content that contradicts a stored observation


def fs_counts(conn: sqlite3.Connection, run_id: str) -> FsCounts:
    row = conn.execute(
        "SELECT COUNT(*) AS observations, COALESCE(SUM(sha256 IS NOT NULL), 0) AS sightings, "
        "       COUNT(DISTINCT sha256) AS uniq, "
        "       COALESCE(SUM(parse_status IN ('malformed', 'unsupported', 'too_large', 'access_denied', 'read_error')), 0) AS failures "
        "FROM fs_observations WHERE run_id = ?", (run_id,)).fetchone()
    repeats = conn.execute(
        "SELECT COUNT(*) FROM (SELECT ROW_NUMBER() OVER (PARTITION BY path, sha256 ORDER BY seq) AS n "
        "FROM fs_observations WHERE run_id = ? AND sha256 IS NOT NULL) WHERE n > 1", (run_id,)).fetchone()[0]
    by_status = {r[0]: r[1] for r in conn.execute(
        "SELECT parse_status, COUNT(*) FROM fs_observations WHERE run_id = ? GROUP BY parse_status", (run_id,))}
    by_validity = {r[0]: r[1] for r in conn.execute(
        "SELECT validity_status, COUNT(*) FROM fs_observations WHERE run_id = ? AND validity_status IS NOT NULL "
        "GROUP BY validity_status", (run_id,))}
    issues = conn.execute("SELECT COUNT(*) FROM run_issues WHERE run_id = ?", (run_id,)).fetchone()[0]
    rejected = conn.execute("SELECT COUNT(DISTINCT seq) FROM run_issues WHERE run_id = ? AND source = 'backend' "
                            "AND kind = 'rejected_record'", (run_id,)).fetchone()[0]
    conflicts = conn.execute("SELECT COUNT(DISTINCT seq) FROM run_issues WHERE run_id = ? AND source = 'backend' "
                             "AND kind = 'seq_conflict'", (run_id,)).fetchone()[0]
    return FsCounts(row["observations"], row["sightings"], row["uniq"], row["sightings"] - row["uniq"], repeats,
                    row["failures"], by_status, by_validity, issues, rejected, conflicts)


def list_fs_observations(conn: sqlite3.Connection, run_id: str, *, parse_status: str | None = None,
                         validity_status: str | None = None, sha256: str | None = None, path: str | None = None,
                         limit: int = 100, offset: int = 0) -> list[dict]:
    """Observations of a run in seq order, joined with their certificate. Filters are optional (exact match)."""
    if parse_status is not None and parse_status not in PARSE_STATUSES:
        raise ValueError("unknown parse_status")
    if validity_status is not None and validity_status not in VALIDITY_STATUSES:
        raise ValueError("unknown validity_status")
    limit, offset = _page(limit, offset)
    rows = conn.execute(
        _OBSERVATION_SELECT +
        "WHERE o.run_id = ?1 AND (?2 IS NULL OR o.parse_status = ?2) AND (?3 IS NULL OR o.validity_status = ?3) "
        "  AND (?4 IS NULL OR o.sha256 = ?4) AND (?5 IS NULL OR o.path = ?5) "
        "ORDER BY o.seq LIMIT ?6 OFFSET ?7",
        (run_id, parse_status, validity_status, sha256, path, limit, offset)).fetchall()
    return [_observation_dict(r) for r in rows]


def _observation_dict(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["warnings"] = json.loads(out.pop("warnings_json"))
    san = out.pop("san_json")
    out["san"] = None if san is None else json.loads(san)
    for flag in ("extension_mismatch", "not_yet_valid", "is_ca"):
        if out[flag] is not None:
            out[flag] = bool(out[flag])
    return out


def get_certificate(conn: sqlite3.Connection, sha256: str) -> dict | None:
    """The certificate identity plus every place and run it was seen."""
    row = conn.execute("SELECT * FROM certificates WHERE sha256 = ?", (sha256,)).fetchone()
    if row is None:
        return None
    out = dict(row)
    out["san"] = json.loads(out.pop("san_json"))
    out["is_ca"] = None if out["is_ca"] is None else bool(out["is_ca"])
    out["sightings"] = conn.execute("SELECT COUNT(*) FROM fs_observations WHERE sha256 = ?", (sha256,)).fetchone()[0]
    out["runs"] = [dict(r) for r in conn.execute(
        "SELECT o.run_id, r.run_number, COUNT(*) AS sightings, COUNT(DISTINCT o.path) AS paths "
        "FROM fs_observations AS o JOIN runs AS r ON r.run_id = o.run_id "
        "WHERE o.sha256 = ? GROUP BY o.run_id ORDER BY r.run_number", (sha256,))]
    return out


def list_run_issues(conn: sqlite3.Connection, run_id: str, *, limit: int = 1000, offset: int = 0) -> list[dict]:
    limit, offset = _page(limit, offset)
    return [dict(r) for r in conn.execute(
        "SELECT id, source, kind, code, path, seq FROM run_issues WHERE run_id = ? ORDER BY id LIMIT ? OFFSET ?",
        (run_id, limit, offset))]
