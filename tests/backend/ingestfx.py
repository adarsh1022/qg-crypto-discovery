"""Builders for ingestion tests: valid records, scan summaries and ready-to-use running runs."""
import copy
import datetime as dt

from agent.x509_parse import assess_validity           # Phase 1 is the oracle for validity facts
from backend import fs_ingest, runs

NOW = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
STAMP = "2026-03-01T12:00:00Z"


def at(seconds):
    return NOW + dt.timedelta(seconds=seconds)


def sha(n: int) -> str:
    return f"{n:064x}"


def _utc(text: str) -> dt.datetime:
    return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def derive_consistent_facts(record: dict, *, given, expiring_days: int = 30) -> None:
    """Fill the derived claims of an ok record the way the agent would: validity from the dates, confidence from the
    warnings. Anything the test set explicitly (`given`) is left alone, so tests can still build contradictions."""
    if record["parse_status"] != "ok":
        return
    try:
        verdict = assess_validity(_utc(record["not_before"]), _utc(record["not_after"]), _utc(record["discovered_at"]),
                                  expiring_days)
    except (TypeError, ValueError):                                    # a test deliberately corrupted a date: leave the rest
        verdict = None
    for field, value in ((("days_to_expiry", verdict.days_to_expiry), ("validity_status", verdict.status),
                          ("not_yet_valid", verdict.not_yet_valid)) if verdict else ()):
        if field not in given:
            record[field] = value
    if "evidence_confidence" not in given:
        record["evidence_confidence"] = "medium" if record["warnings"] else "high"


def ok_record(path=r"C:\app\server.pem", n=1, **overrides) -> dict:
    """A valid certificate sighting. The same `n` always means the same certificate (same facts)."""
    record = dict(
        path=path, filename=path.replace("/", "\\").rsplit("\\", 1)[-1], scan_root=path.replace("/", "\\").rsplit("\\", 1)[0],
        format="pem", discovered_at=STAMP, sha256=sha(n), serial_hex=f"{n:x}", subject=f"CN=cert{n}", issuer="CN=Test CA",
        san=[{"type": "DNS", "value": f"host{n}.example"}], chain_index=0, chain_total=1, chain_role="leaf",
        key_algorithm="RSA", key_size=2048, key_curve=None, signature_algorithm="sha256WithRSAEncryption",
        not_before="2025-01-01T00:00:00Z", not_after="2027-01-01T00:00:00Z", days_to_expiry=306,
        validity_status="valid", not_yet_valid=False, is_ca=False, warnings=[], parse_status="ok", detail=None,
        access_error=None, evidence_confidence="high", extension_mismatch=False, duplicate_in_scan=False,
        owning_process=None)
    record.update(overrides)
    derive_consistent_facts(record, given=overrides)
    return record


def pfx_record(path=r"C:\app\bundle.pfx", n=1, **overrides) -> dict:
    fields = dict(format="pkcs12", chain_index=None, chain_total=3)
    fields.update(overrides)
    return ok_record(path, n, **fields)


def failure_record(path=r"C:\app\locked.pem", status="access_denied", **overrides) -> dict:
    record = dict.fromkeys(ok_record(), None)
    record.update(path=path, filename=path.rsplit("\\", 1)[-1], scan_root=path.rsplit("\\", 1)[0], format="unknown",
                  discovered_at=STAMP, warnings=[], parse_status=status, detail="read_failed",
                  access_error="PermissionError:WinError 5" if status == "access_denied" else None,
                  evidence_confidence="low", extension_mismatch=False, duplicate_in_scan=False)
    record.update(overrides)
    return record


def summary(records: int, *, stop_reason="completed", roots=((r"C:\app", "scanned"),), errors=(), errors_total=None,
            bundles_truncated=0, **extra) -> dict:
    listed = [dict(e) for e in errors]
    out = dict(roots=[{"root": r, "status": s} for r, s in roots], directories_visited=1, entries_visited=records,
               candidate_files=records, files_read=records, records=records, records_by_status={}, unique_certificates=0,
               duplicate_observations=0, bundles_truncated=bundles_truncated, skipped={}, errors=listed,
               errors_total=len(listed) if errors_total is None else errors_total, stop_reason=stop_reason,
               complete=stop_reason == "completed", elapsed_seconds=1.5)
    out.update(extra)
    return out


def dir_error(path=r"C:\app\private", kind="listdir", code="PermissionError:WinError 5") -> dict:
    return dict(path=path, kind=kind, code=code)


def running_run(conn, *, run_type="filesystem", trigger="manual", config=None) -> str:
    run_id = runs.create_run(conn, run_type, trigger, now=NOW, config=config)
    runs.start_run(conn, run_id, now=at(1))
    return run_id


def ingest(conn, run_id, records, *, start=0, now=None):
    return fs_ingest.ingest_fs_batch(conn, run_id, fs_ingest.number_records(records, start=start), now=now or at(2))


def finish(conn, run_id, records_count, **kwargs):
    kwargs.setdefault("summary", summary(records_count))
    return fs_ingest.finalize_fs_run(conn, run_id, now=at(10), **kwargs)


def deep(record):
    return copy.deepcopy(record)
