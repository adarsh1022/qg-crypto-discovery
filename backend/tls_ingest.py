"""Persist TLS-scan results: validate -> store observations -> finalize with counts derived from the database.

This mirrors fs_ingest and reuses its machinery (the (seq, record) envelope, first-write-wins rejections, seq conflicts,
the certificate catalog upsert). What is different is what a TLS record is: ONE ACTIVE PROBE ATTEMPT against a listener on this
machine, never a passively observed connection (see tls_record).

Semantics
* Identity.  An observation is identified by (run_id, seq). A certificate is identified by the SHA-256 of its DER: one
  `certificates` row, ever, shared with filesystem results. A chain keeps its order in tls_peer_certificates.position
  (leaf first); the same fingerprint may appear at two positions.
* Replays.  Re-sending (seq, record) with identical content is a no-op (`duplicates`). Re-sending a stored seq with DIFFERENT
  content is a conflict: one `seq_conflict` issue, the stored row is never touched, the run becomes partial.
* Rejections.  A bad record never stops the batch; it becomes a `rejected_record` issue with a fixed code and the seq.
  A record whose certificate has the same fingerprint as a stored one but different facts is rejected
  (`certificate_identity_conflict`) BEFORE anything is written for it: no observation, no partial catalog update.
* Counts come from stored rows, never from the agent:
    records   stored observations (every probe attempt that produced a record)
    findings  stored observations whose handshake COMPLETED. A failed, incomplete, alert or unknown probe is stored as evidence
              but is NOT a TLS finding, and a non-TLS listener never counts as a TLS service.
    rejected  distinct seqs the backend refused
    errors    agent-reported scan errors (enumeration failure, a probe that could not be made, a policy/locality refusal).
              Known wording limitation: the reason token for this count is the one shared with filesystem runs, `file_errors:N`
              (backend/run_state.decide_outcome); for a TLS run it means scan errors, not files. It is not renamed because the
              token is filesystem behavior that existing tests and the UI rely on.
  A refused or timed-out probe is an observation, not an error. Listeners the policy skipped are in the stored agent summary.
* Authority.  The agent's summary can add coverage gaps (a stop reason other than "completed", a failed enumeration) but cannot
  remove one the stored evidence shows. Its totals are cross-checked against what was stored; a disagreement is a
  `count_mismatch` (the run becomes partial). A successful enumeration with zero eligible listeners completes with zero records;
  a failed enumeration with nothing recorded fails the run (`no_usable_data`).
* Atomicity.  Same transaction ownership as fs_ingest: the *_in_tx functions run inside a transaction the CALLER holds.
"""
from __future__ import annotations

import datetime as dt
import sqlite3
from typing import Any, Iterable

from . import run_state as rs
from .db import require_transaction
from .fs_ingest import (REJECTED, SEQ_CONFLICT, BatchResult, _certificate_upserted, _check_batch, _conflict, _reject,
                        _seq_was_rejected, _writable_run, seq_conflict_count)
from .fs_record import CERT_COLUMNS, RecordRejected, canonical_json
from .runs import save_state
from .tls_record import (ERROR_KINDS, MAX_LISTED_ERRORS, OBSERVATION_COLUMNS, TlsSummaryFacts, ValidTlsRecord, as_fs_valid_record,
                         parse_tls_summary, validate_tls_record)

RUN_TYPE = "tls"


# ------------------------------------------------------------------ batch ingestion
def ingest_tls_batch_in_tx(conn: sqlite3.Connection, run_id: str, items: Iterable[tuple[int, Any] | list], *,
                           now: dt.datetime) -> BatchResult:
    """Validate and store a batch of (seq, record) pairs for a RUNNING tls run, inside the caller's transaction."""
    require_transaction(conn)
    pairs = _check_batch(items)
    state = _writable_run(conn, run_id, RUN_TYPE)
    accepted = duplicates = 0
    rejected: list[tuple[int, str]] = []
    conflicts: list[int] = []
    for seq, record in pairs:
        outcome = _ingest_one(conn, run_id, seq, record)
        if outcome == "accepted":
            accepted += 1
        elif outcome == "duplicate":
            duplicates += 1
        elif outcome == SEQ_CONFLICT:
            conflicts.append(seq)
        else:
            rejected.append((seq, outcome))
    progress = rs.update_counts(rs.heartbeat(state, now), derived_counts(conn, run_id))
    save_state(conn, run_id, progress, expected_status=rs.RUNNING)
    return BatchResult(accepted, duplicates, tuple(rejected), tuple(conflicts))


def _ingest_one(conn: sqlite3.Connection, run_id: str, seq: int, record: Any) -> str:
    """-> 'accepted' | 'duplicate' | 'seq_conflict' | a rejection code."""
    existing = _stored(conn, run_id, seq)
    if existing is None and _seq_was_rejected(conn, run_id, seq):
        return "duplicate"
    try:
        valid = validate_tls_record(record)
    except RecordRejected as rejection:
        if existing is not None:                       # the seq holds an observation: contradicting data, not a bad record
            return _conflict(conn, run_id, seq, record)
        return _reject(conn, run_id, seq, record, rejection.code)
    if existing is not None:
        return "duplicate" if existing == _comparable(valid) else _conflict(conn, run_id, seq, record)
    if _identity_conflict(conn, valid):
        return _reject(conn, run_id, seq, record, "certificate_identity_conflict")
    for certificate in valid.certificates:
        _certificate_upserted(conn, run_id, as_fs_valid_record(valid, certificate))      # cannot refuse: checked above
    columns = ("run_id", "seq", *OBSERVATION_COLUMNS)
    cursor = conn.execute(f"INSERT INTO tls_observations ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))})",
                          (run_id, seq, *(valid.observation[c] for c in OBSERVATION_COLUMNS)))
    observation_id = cursor.lastrowid
    conn.executemany("INSERT INTO tls_peer_certificates (tls_observation_id, position, sha256) VALUES (?, ?, ?)",
                     [(observation_id, position, cert["sha256"]) for position, cert in enumerate(valid.certificates)])
    return "accepted"


def _identity_conflict(conn: sqlite3.Connection, valid: ValidTlsRecord) -> bool:
    """True if any certificate of this record has a fingerprint that is already known (in the catalog, or earlier in this very
    record) with DIFFERENT facts. Nothing is written for such a record."""
    seen: dict[str, dict] = {}
    for certificate in valid.certificates:
        if seen.setdefault(certificate["sha256"], certificate) != certificate:
            return True
        current = conn.execute(f"SELECT {', '.join(CERT_COLUMNS)} FROM certificates WHERE sha256 = ?",
                               (certificate["sha256"],)).fetchone()
        if current is not None and dict(current) != certificate:
            return True
    return False


def _stored(conn: sqlite3.Connection, run_id: str, seq: int) -> dict | None:
    row = conn.execute(f"SELECT id, {', '.join(OBSERVATION_COLUMNS)} FROM tls_observations WHERE run_id = ? AND seq = ?",
                       (run_id, seq)).fetchone()
    if row is None:
        return None
    stored = dict(row)
    observation_id = stored.pop("id")
    stored["_peers"] = [r[0] for r in conn.execute(
        "SELECT sha256 FROM tls_peer_certificates WHERE tls_observation_id = ? ORDER BY position", (observation_id,))]
    return stored


def _comparable(valid: ValidTlsRecord) -> dict:
    return {**valid.observation, "_peers": [c["sha256"] for c in valid.certificates]}


# ------------------------------------------------------------------ counts derived from stored rows
def derived_counts(conn: sqlite3.Connection, run_id: str) -> rs.Counts:
    """The four run counters, computed from what is stored (never from the agent)."""
    row = conn.execute("SELECT COUNT(*) AS records, COALESCE(SUM(handshake_outcome = 'completed'), 0) AS findings "
                       "FROM tls_observations WHERE run_id = ?", (run_id,)).fetchone()
    rejected = conn.execute("SELECT COUNT(DISTINCT seq) FROM run_issues WHERE run_id = ? AND source = 'backend' AND kind = ?",
                            (run_id, REJECTED)).fetchone()[0]
    return rs.Counts(records=row["records"], findings=row["findings"], rejected=rejected, errors=agent_error_count(conn, run_id))


def agent_error_count(conn: sqlite3.Connection, run_id: str) -> int:
    marks = ", ".join("?" * len(ERROR_KINDS))
    return conn.execute(f"SELECT COUNT(*) FROM run_issues WHERE run_id = ? AND source = 'agent' AND kind IN ({marks})",
                        (run_id, *ERROR_KINDS)).fetchone()[0]


def _stored_completed(conn: sqlite3.Connection, run_id: str) -> int:
    return conn.execute("SELECT COUNT(*) FROM tls_observations WHERE run_id = ? AND handshake_outcome = 'completed'",
                        (run_id,)).fetchone()[0]


def _distinct_seqs(conn: sqlite3.Connection, run_id: str) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM (SELECT seq FROM tls_observations WHERE run_id = ? "
        "UNION SELECT seq FROM run_issues WHERE run_id = ? AND source = 'backend' AND kind = ? AND seq IS NOT NULL)",
        (run_id, run_id, REJECTED)).fetchone()[0]


# ------------------------------------------------------------------ finalization
def finalize_tls_run_in_tx(conn: sqlite3.Connection, run_id: str, *, now: dt.datetime, outcome: str = "finished",
                           summary: Any = None, fatal_code: str | None = None, agent_lost: bool = False) -> rs.RunState:
    """End a running tls run and set its final status from the stored evidence (the same outcomes as finalize_fs_run_in_tx).

    outcome   'finished'  the agent ended normally (pass TlsScan.summary)
              'failed'    the agent reported a fatal failure (fatal_code is a short code such as 'invalid_config')
              'lost'      the agent vanished (no summary)
              'cancelled' the backend ended a run whose cancellation was never answered (agent_lost: it also went silent)
    """
    require_transaction(conn)
    if outcome not in rs.OUTCOMES:
        raise ValueError(f"outcome must be one of {rs.OUTCOMES}")
    facts = parse_tls_summary(summary) if summary is not None else None
    state = _writable_run(conn, run_id, RUN_TYPE)
    if facts is not None:
        conn.executemany("INSERT INTO run_issues (run_id, source, kind, code) VALUES (?, 'agent', ?, ?)",
                         [(run_id, kind, code) for kind, code in facts.errors])
    if summary is not None and facts is None:
        conn.execute("INSERT INTO run_issues (run_id, source, kind, code) VALUES (?, 'backend', 'summary', 'summary_invalid')",
                     (run_id,))
    counts = derived_counts(conn, run_id)
    report = _agent_report(conn, run_id, outcome, facts, counts, fatal_code, agent_lost, state.cancel_requested)
    final = rs.finish(state, now, counts, report)
    stored = None if facts is None else canonical_json(facts.stored)
    save_state(conn, run_id, final, expected_status=rs.RUNNING, agent_summary_json=stored)
    return final


def _agent_report(conn: sqlite3.Connection, run_id: str, outcome: str, facts: TlsSummaryFacts | None, counts: rs.Counts,
                  fatal_code: str | None, agent_lost: bool, cancel_requested: bool) -> rs.AgentReport:
    conflicts = seq_conflict_count(conn, run_id)
    if facts is None:
        return rs.AgentReport(outcome=outcome, coverage_started=counts.records > 0, seq_conflicts=conflicts,
                              agent_lost=agent_lost, cancel_requested=cancel_requested, fatal_code=fatal_code)
    return rs.AgentReport(
        outcome=outcome, stop_reason=facts.stop_reason,
        coverage_started=facts.enumeration == "ok" or counts.records > 0,       # enumeration worked, or evidence exists
        count_mismatch=_counts_disagree(conn, run_id, facts), seq_conflicts=conflicts, agent_lost=agent_lost,
        cancel_requested=cancel_requested, fatal_code=fatal_code)


def _counts_disagree(conn: sqlite3.Connection, run_id: str, facts: TlsSummaryFacts) -> bool:
    """The agent's own totals must reconcile with what the backend stored, or evidence is missing."""
    if facts.records is None or facts.records != _distinct_seqs(conn, run_id):
        return True
    if facts.handshakes_completed is None or facts.handshakes_completed != _stored_completed(conn, run_id):
        return True
    if facts.invalid_errors:
        return True
    listed = len(facts.errors)
    return facts.errors_total is None or (facts.errors_total != listed and not (listed >= MAX_LISTED_ERRORS and facts.errors_total > listed))

