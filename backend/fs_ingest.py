"""Persist filesystem-scan results: validate -> store observations -> finalize with counts from the database.

Semantics (relied on by tests and by the later API):

* Identity.  A certificate is identified by the SHA-256 of its DER: one `certificates` row, ever.
  A sighting (`fs_observations` row) is identified by (run_id, seq). `seq` is the agent's per-run record
  counter, carried in the upload envelope: items are (seq, record) pairs. Nothing is ever merged by
  fingerprint, so the same certificate in two files, twice in one PKCS#12 file, or in two runs gives
  separate sightings.
* Replays.  Re-sending (seq, record) with identical content is a no-op (`duplicates`). Re-sending a seq that
  already holds a stored observation with DIFFERENT content (or with content that is not even valid) is a
  conflict: the agent and the backend disagree about what that seq means. The stored row is never touched, one
  `seq_conflict` issue is recorded per seq, and the run becomes partial. A conflict is not an ordinary
  rejection: it is reported separately (`BatchResult.conflicts`, reason `seq_conflicts:N`) and does not count
  towards `rejected`. A seq that was rejected stays rejected (first write wins), so a replay cannot create a
  second issue or flip an outcome.
* Rejections.  A bad record never stops the batch: valid records are stored, the bad one (whose seq holds no
  stored observation) becomes a `rejected_record` issue carrying only a fixed code, the seq and (if clean) its path.
* Derived claims.  A certificate record's validity status, days to expiry, not-yet-valid flag and confidence must
  agree with its dates, warnings and the run's `expiring_days` (see fs_record.validate_fs_record).
* Order.  `entry_ordinal` is the position of a record among the run's records for the same path, in
  seq order, recomputed whenever a batch touches a path, so it does not depend on arrival order.
* Read errors.  An agent-reported `read` error is resolved when a stored access_denied/read_error observation for
  the same path and error code exists (it is then counted once, as that observation). A `read` error with no such
  observation is unresolved and counts as an error, like root/listdir/stat errors, so the run is partial.
* Scan policy is not failure.  depth_limit, excluded directories, reparse/symlink skips, cloud placeholders,
  files over the size limit and overlapping roots are intentional boundaries: they never make a run partial.
  They stay visible as `skipped` / `too_large` observations and in the stored agent summary.
* Authority.  Counts and the final status come from stored rows. The agent's summary is a set of claims:
  it can add coverage gaps (limits, truncated bundles, unreached roots) but can never remove one that the
  stored evidence shows (a summary saying "completed" cannot override stored read errors).
* Roots.  If the run's configuration names explicit roots, every one of them must appear in the agent's
  summary (any status; 'overlap' counts as reported). A requested root the summary never mentions counts as a
  root that was not scanned, so the run is partial. Roots are compared after Phase 1's own normalisation.
* Batch items.  Each item is a pair (seq, record), given as a tuple or as a two-element list (what JSON
  produces); both are normalised to the same representation before anything is stored.
* Atomicity.  Each public function runs in one db.transaction. Invalid records are handled inside it;
  any unexpected error rolls the whole batch back. Transaction ownership is explicit: `ingest_fs_batch` and
  `finalize_fs_run` open their own transaction around `ingest_fs_batch_in_tx` / `finalize_fs_run_in_tx`, which do the
  same work inside a transaction the CALLER holds (they refuse to run without one), so a service can make "check the
  run, expire it, ingest" one atomic step without any nested-transaction semantics.
"""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable

from . import run_state as rs
from .db import require_transaction, transaction
from .fs_record import (CERT_COLUMNS, DIRECTORY_LEVEL_ERROR_KINDS, MAX_PATH, OBSERVATION_COLUMNS, RecordRejected,
                        SummaryFacts, ValidRecord, canonical_json, expiring_days_from_config, parse_summary,
                        requested_roots, unreported_roots, validate_fs_record)
from .runs import RunNotFound, WrongRunType, load_state, save_state
from .safety import has_pem_armor, sanitize_text

REJECTED = "rejected_record"
SEQ_CONFLICT = "seq_conflict"
FILE_ERROR_STATUSES = ("access_denied", "read_error")


class BatchRejected(ValueError):
    """The batch itself is malformed (not a sequence of (seq, record) pairs); nothing was stored."""


class RunNotWritable(rs.InvalidTransition):
    """Records can only be added to a running run."""


@dataclass(frozen=True)
class BatchResult:
    accepted: int                              # new observations stored
    duplicates: int                            # exact replays (and replays of already-rejected seqs): no change
    rejected: tuple[tuple[int, str], ...]      # (seq, code) newly rejected in this batch (never stored)
    conflicts: tuple[int, ...] = ()            # seqs newly found to contradict an already stored observation


def number_records(records: Iterable[dict], *, start: int = 0) -> list[tuple[int, dict]]:
    """Wrap a scan's records in the (seq, record) envelope. The uploader numbers records 0, 1, 2, ... per run."""
    return list(enumerate(records, start))


# ------------------------------------------------------------------ batch ingestion
def ingest_fs_batch(conn: sqlite3.Connection, run_id: str, items: Iterable[tuple[int, Any] | list], *,
                    now: dt.datetime) -> BatchResult:
    pairs = _check_batch(items)                       # a malformed batch is refused before the write lock is taken
    with transaction(conn):
        return ingest_fs_batch_in_tx(conn, run_id, pairs, now=now)


def ingest_fs_batch_in_tx(conn: sqlite3.Connection, run_id: str, items: Iterable[tuple[int, Any] | list], *,
                          now: dt.datetime) -> BatchResult:
    """ingest_fs_batch inside a transaction the caller holds. Normalises the items itself (a no-op if already done)."""
    require_transaction(conn)
    pairs = _check_batch(items)
    accepted = duplicates = 0
    rejected: list[tuple[int, str]] = []
    conflicts: list[int] = []
    touched_paths: set[str] = set()
    state = _writable_run(conn, run_id)
    expiring_days = expiring_days_from_config(_run_config(conn, run_id))
    for seq, record in pairs:
        outcome = _ingest_one(conn, run_id, seq, record, touched_paths, expiring_days)
        if outcome == "accepted":
            accepted += 1
        elif outcome == "duplicate":
            duplicates += 1
        elif outcome == SEQ_CONFLICT:
            conflicts.append(seq)
        else:
            rejected.append((seq, outcome))
    for path in sorted(touched_paths):
        _renumber_ordinals(conn, run_id, path)
    counts = derived_counts(conn, run_id)
    progress = rs.update_counts(rs.heartbeat(state, now), counts)
    save_state(conn, run_id, progress, expected_status=rs.RUNNING)
    return BatchResult(accepted, duplicates, tuple(rejected), tuple(conflicts))


def _check_batch(items: Iterable[tuple[int, Any] | list]) -> list[tuple[int, Any]]:
    """Normalise every item to a (seq, record) tuple; tuples and two-element lists are both accepted."""
    try:
        raw = list(items)
    except TypeError:
        raise BatchRejected("batch must be an iterable of (seq, record) pairs") from None
    pairs = []
    for pair in raw:
        if not (isinstance(pair, (tuple, list)) and len(pair) == 2):
            raise BatchRejected("each item must be a (seq, record) pair")
        seq, record = pair
        if isinstance(seq, bool) or not isinstance(seq, int) or not 0 <= seq < 2**31:
            raise BatchRejected("seq must be a non-negative integer")
        pairs.append((seq, record))
    return pairs


def _writable_run(conn: sqlite3.Connection, run_id: str, run_type: str = "filesystem") -> rs.RunState:
    row = conn.execute("SELECT type, status FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise RunNotFound(run_id)
    if row["type"] != run_type:
        raise WrongRunType(f"not a {run_type} run")
    if row["status"] != rs.RUNNING:
        raise RunNotWritable(f"cannot add records to a {row['status']} run")
    return load_state(conn, run_id)


def _ingest_one(conn: sqlite3.Connection, run_id: str, seq: int, record: Any, touched: set[str],
                expiring_days: int) -> str:
    """-> 'accepted' | 'duplicate' | 'seq_conflict' | a rejection code."""
    existing = _stored_observation(conn, run_id, seq)
    if existing is None and _seq_was_rejected(conn, run_id, seq):
        return "duplicate"
    try:
        valid = validate_fs_record(record, expiring_days=expiring_days)
    except RecordRejected as rejection:
        if existing is not None:                       # the seq holds an observation: contradicting data, not a bad record
            return _conflict(conn, run_id, seq, record)
        return _reject(conn, run_id, seq, record, rejection.code)
    if existing is not None:
        return "duplicate" if existing == valid.observation else _conflict(conn, run_id, seq, record)
    if valid.certificate is not None and not _certificate_upserted(conn, run_id, valid):
        return _reject(conn, run_id, seq, record, "certificate_identity_conflict")
    columns = ("run_id", "seq", "entry_ordinal", *OBSERVATION_COLUMNS)
    values = (run_id, seq, 0, *(valid.observation[c] for c in OBSERVATION_COLUMNS))
    conn.execute(f"INSERT INTO fs_observations ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))})", values)
    touched.add(valid.observation["path"])
    return "accepted"


def _stored_observation(conn: sqlite3.Connection, run_id: str, seq: int) -> dict | None:
    row = conn.execute(f"SELECT {', '.join(OBSERVATION_COLUMNS)} FROM fs_observations WHERE run_id = ? AND seq = ?",
                       (run_id, seq)).fetchone()
    return None if row is None else dict(row)


# "Has the backend already recorded an issue of this kind for this seq?"  Used for both kinds of per-seq backend issue
# (rejected_record, seq_conflict). Served by idx_run_issues_kind_seq (run_id, kind, seq), migration 0002; without it
# every lookup scanned all issues of the run.
REJECTED_LOOKUP_SQL = "SELECT 1 FROM run_issues WHERE run_id = ? AND kind = ? AND seq = ? AND source = 'backend' LIMIT 1"


def _seq_was_rejected(conn: sqlite3.Connection, run_id: str, seq: int) -> bool:
    return conn.execute(REJECTED_LOOKUP_SQL, (run_id, REJECTED, seq)).fetchone() is not None


def _seq_has_conflict(conn: sqlite3.Connection, run_id: str, seq: int) -> bool:
    return conn.execute(REJECTED_LOOKUP_SQL, (run_id, SEQ_CONFLICT, seq)).fetchone() is not None


def _conflict(conn: sqlite3.Connection, run_id: str, seq: int, record: Any) -> str:
    """Record that a stored seq was re-sent with contradicting content (once per seq; later replays add nothing)."""
    if _seq_has_conflict(conn, run_id, seq):
        return "duplicate"
    conn.execute("INSERT INTO run_issues (run_id, source, kind, code, path, seq) VALUES (?, 'backend', ?, ?, ?, ?)",
                 (run_id, SEQ_CONFLICT, SEQ_CONFLICT, _issue_path(record), seq))
    return SEQ_CONFLICT


def _reject(conn: sqlite3.Connection, run_id: str, seq: int, record: Any, code: str) -> str:
    if _seq_was_rejected(conn, run_id, seq):             # first write wins: a replay adds nothing
        return "duplicate"
    conn.execute("INSERT INTO run_issues (run_id, source, kind, code, path, seq) VALUES (?, 'backend', ?, ?, ?, ?)",
                 (run_id, REJECTED, code, _issue_path(record), seq))
    return code


def _issue_path(record: Any) -> str | None:
    """The record's path, only if it is clean enough to repeat in an issue."""
    path = record.get("path") if isinstance(record, dict) else None
    if not isinstance(path, str) or not path:
        return None
    path = sanitize_text(path)
    return path if len(path) <= MAX_PATH and not has_pem_armor(path) else None


def _certificate_upserted(conn: sqlite3.Connection, run_id: str, valid: ValidRecord) -> bool:
    """Store the certificate identity once. False if the fingerprint is already stored with different facts."""
    cert = valid.certificate
    stamp = valid.observation["discovered_at"]
    current = conn.execute(f"SELECT {', '.join(CERT_COLUMNS)} FROM certificates WHERE sha256 = ?", (cert["sha256"],)).fetchone()
    if current is not None and dict(current) != cert:
        return False                                    # same fingerprint, different facts: refuse, never overwrite
    conn.execute(
        f"INSERT INTO certificates ({', '.join(CERT_COLUMNS)}, first_seen_run, first_seen_at, last_seen_run, last_seen_at) "
        f"VALUES ({', '.join('?' * len(CERT_COLUMNS))}, ?, ?, ?, ?) "
        "ON CONFLICT (sha256) DO UPDATE SET "
        "first_seen_run = CASE WHEN excluded.first_seen_at < certificates.first_seen_at "
        "                      THEN excluded.first_seen_run ELSE certificates.first_seen_run END, "
        "first_seen_at = MIN(excluded.first_seen_at, certificates.first_seen_at), "
        "last_seen_run = CASE WHEN excluded.last_seen_at >= certificates.last_seen_at "
        "                     THEN excluded.last_seen_run ELSE certificates.last_seen_run END, "
        "last_seen_at = MAX(excluded.last_seen_at, certificates.last_seen_at)",
        (*(cert[c] for c in CERT_COLUMNS), run_id, stamp, run_id, stamp))
    return True


def _renumber_ordinals(conn: sqlite3.Connection, run_id: str, path: str) -> None:
    conn.execute(
        "UPDATE fs_observations SET entry_ordinal = ("
        "  SELECT COUNT(*) FROM fs_observations AS earlier "
        "  WHERE earlier.run_id = fs_observations.run_id AND earlier.path = fs_observations.path "
        "    AND earlier.seq < fs_observations.seq) "
        "WHERE run_id = ? AND path = ?", (run_id, path))


# ------------------------------------------------------------------ counts derived from stored rows
def derived_counts(conn: sqlite3.Connection, run_id: str) -> rs.Counts:
    """The four run counters, computed from what is stored (never from the agent).

    records   stored observations                      findings  stored certificate sightings (parse_status ok)
    rejected  distinct seqs refused by the backend     errors    unreadable files + directory-level scan errors
    """
    marks = ", ".join("?" * len(FILE_ERROR_STATUSES))
    row = conn.execute(
        "SELECT COUNT(*) AS records, "
        "       COALESCE(SUM(parse_status = 'ok'), 0) AS findings, "
        f"      COALESCE(SUM(parse_status IN ({marks})), 0) AS file_errors "
        "FROM fs_observations WHERE run_id = ?", (*FILE_ERROR_STATUSES, run_id)).fetchone()
    rejected = conn.execute("SELECT COUNT(DISTINCT seq) FROM run_issues WHERE run_id = ? AND source = 'backend' AND kind = ?",
                            (run_id, REJECTED)).fetchone()[0]
    kinds = ", ".join("?" * len(DIRECTORY_LEVEL_ERROR_KINDS))
    directory_errors = conn.execute(
        f"SELECT COUNT(*) FROM run_issues WHERE run_id = ? AND source = 'agent' AND kind IN ({kinds})",
        (run_id, *DIRECTORY_LEVEL_ERROR_KINDS)).fetchone()[0]
    return rs.Counts(records=row["records"], findings=row["findings"], rejected=rejected,
                     errors=row["file_errors"] + directory_errors + unresolved_read_errors(conn, run_id))


def unresolved_read_errors(conn: sqlite3.Connection, run_id: str) -> int:
    """Agent-reported `read` errors with no stored access_denied/read_error observation for the same path and code.

    A resolved read error is already counted, once, as that observation; counting it here as well would double count.
    """
    marks = ", ".join("?" * len(FILE_ERROR_STATUSES))
    return conn.execute(
        "SELECT COUNT(*) FROM run_issues AS issue WHERE issue.run_id = ? AND issue.source = 'agent' AND issue.kind = 'read' "
        "AND NOT EXISTS (SELECT 1 FROM fs_observations AS seen WHERE seen.run_id = issue.run_id AND seen.path = issue.path "
        f"AND seen.access_error = issue.code AND seen.parse_status IN ({marks}))",
        (run_id, *FILE_ERROR_STATUSES)).fetchone()[0]


def seq_conflict_count(conn: sqlite3.Connection, run_id: str) -> int:
    return conn.execute("SELECT COUNT(DISTINCT seq) FROM run_issues WHERE run_id = ? AND source = 'backend' AND kind = ?",
                        (run_id, SEQ_CONFLICT)).fetchone()[0]


def _distinct_seqs_seen(conn: sqlite3.Connection, run_id: str) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM (SELECT seq FROM fs_observations WHERE run_id = ? "
        "UNION SELECT seq FROM run_issues WHERE run_id = ? AND source = 'backend' AND kind = ? AND seq IS NOT NULL)",
        (run_id, run_id, REJECTED)).fetchone()[0]


# ------------------------------------------------------------------ finalization
def finalize_fs_run(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime, outcome: str = "finished",
                    summary: Any = None, fatal_code: str | None = None, agent_lost: bool = False) -> rs.RunState:
    """End a running filesystem run and set its final status from the stored evidence.

    outcome   'finished'  the agent ended normally (pass its Scan.summary)
              'failed'    the agent reported a fatal failure (fatal_code is a short code)
              'lost'      the agent vanished (no summary)
              'cancelled' the backend ended a run whose cancellation was never answered (agent_lost: it also went
                          silent). Always partial: the run did start and was told to stop.
    """
    _check_outcome(outcome)                           # refuse bad input before the write lock is taken
    with transaction(conn):
        return finalize_fs_run_in_tx(conn, run_id, now=now, outcome=outcome, summary=summary, fatal_code=fatal_code,
                                     agent_lost=agent_lost)


def _check_outcome(outcome: str) -> None:
    if outcome not in rs.OUTCOMES:
        raise ValueError(f"outcome must be one of {rs.OUTCOMES}")


def finalize_fs_run_in_tx(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime, outcome: str = "finished",
                          summary: Any = None, fatal_code: str | None = None, agent_lost: bool = False) -> rs.RunState:
    """finalize_fs_run inside a transaction the caller holds."""
    require_transaction(conn)
    _check_outcome(outcome)
    facts = parse_summary(summary) if summary is not None else None
    state = _writable_run(conn, run_id)
    if facts is not None:
        _store_agent_errors(conn, run_id, facts)
    if summary is not None and facts is None:
        conn.execute("INSERT INTO run_issues (run_id, source, kind, code) VALUES (?, 'backend', 'summary', 'summary_invalid')",
                     (run_id,))
    counts = derived_counts(conn, run_id)
    report = _agent_report(conn, run_id, outcome, facts, counts, fatal_code, agent_lost, state.cancel_requested)
    final = rs.finish(state, now, counts, report)
    stored = None if facts is None else canonical_json(facts.stored)
    save_state(conn, run_id, final, expected_status=rs.RUNNING, agent_summary_json=stored)
    return final


def _store_agent_errors(conn: sqlite3.Connection, run_id: str, facts: SummaryFacts) -> None:
    conn.executemany("INSERT INTO run_issues (run_id, source, kind, code, path) VALUES (?, 'agent', ?, ?, ?)",
                     [(run_id, kind, code, path) for path, kind, code in facts.errors])


def _agent_report(conn: sqlite3.Connection, run_id: str, outcome: str, facts: SummaryFacts | None,
                  counts: rs.Counts, fatal_code: str | None, agent_lost: bool = False,
                  cancel_requested: bool = False) -> rs.AgentReport:
    conflicts = seq_conflict_count(conn, run_id)
    if facts is None:
        return rs.AgentReport(outcome=outcome, coverage_started=counts.records > 0, seq_conflicts=conflicts,
                              agent_lost=agent_lost, cancel_requested=cancel_requested, fatal_code=fatal_code)
    return rs.AgentReport(
        outcome=outcome, stop_reason=facts.stop_reason,
        coverage_started=facts.roots_walked > 0 or counts.records > 0,
        roots_not_scanned=facts.roots_not_scanned + _roots_never_reported(conn, run_id, facts),
        truncated_files=facts.bundles_truncated,
        count_mismatch=_counts_disagree(conn, run_id, facts), seq_conflicts=conflicts, agent_lost=agent_lost,
        cancel_requested=cancel_requested, fatal_code=fatal_code)


def _run_config(conn: sqlite3.Connection, run_id: str) -> dict:
    return json.loads(conn.execute("SELECT config_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0])


def _roots_never_reported(conn: sqlite3.Connection, run_id: str, facts: SummaryFacts) -> int:
    """Requested roots (from the run's own configuration) that the agent's summary does not mention."""
    requested = requested_roots(_run_config(conn, run_id))
    return 0 if requested is None else unreported_roots(requested, facts.reported_roots)


def _counts_disagree(conn: sqlite3.Connection, run_id: str, facts: SummaryFacts) -> bool:
    """The agent's own totals must reconcile with what the backend stored, or evidence is missing."""
    if facts.records is None or facts.records != _distinct_seqs_seen(conn, run_id):
        return True
    if facts.invalid_errors:
        return True
    listed = len(facts.errors)
    return facts.errors_total is None or (facts.errors_total != listed and not (listed >= 1000 and facts.errors_total > listed))
