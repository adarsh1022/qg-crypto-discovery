"""Observation records: turn parsed certificate facts into report-ready dicts (pure, stdlib only).

One record per certificate sighting, or one per candidate file that yielded no certificate
(unreadable, malformed, unsupported, ...). No I/O happens here.

Private-key safety: records are built only from CertInfo / FileParse fields, fixed status and
detail codes, and filesystem names. There is no field for file size or raw content, so adding
or removing key blocks in a certificate file cannot change its records.
"""
from __future__ import annotations

import datetime as dt

from .cert_file import FileParse
from .x509_parse import CertInfo, assess_validity

RECORD_FIELDS = (
    # where / when
    "path", "filename", "scan_root", "format", "discovered_at",
    # certificate (null unless parse_status == "ok")
    "sha256", "serial_hex", "subject", "issuer", "san",
    "chain_index", "chain_total", "chain_role",
    "key_algorithm", "key_size", "key_curve", "signature_algorithm",
    "not_before", "not_after", "days_to_expiry", "validity_status", "not_yet_valid",
    "is_ca", "warnings",
    # status / evidence
    "parse_status", "detail", "access_error", "evidence_confidence",
    "extension_mismatch", "duplicate_in_scan",
    # reserved for a later phase
    "owning_process",
)

ENTRY_STATUSES = ("ok", "malformed", "unsupported", "too_large")
FILE_STATUSES = ("no_certificate", "malformed", "unsupported", "too_large",
                 "access_denied", "read_error", "skipped")
ALL_STATUSES = tuple(dict.fromkeys(ENTRY_STATUSES + FILE_STATUSES))


def iso_utc(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_text(value: str) -> str:
    """Make a filesystem-derived string (path, file name, root) safe for strict UTF-8 output.

    Windows file names may contain unpaired UTF-16 surrogates, which Python keeps as lone
    surrogate code points that cannot be encoded as UTF-8. Each one becomes the visible escape
    text (U+D800 -> the six characters \\ud800); every other character, including valid
    non-BMP characters and ordinary backslashes, is left untouched. Deterministic and idempotent.

    Only for metadata that came from the filesystem and is emitted in records or summaries. Never
    use it on a path that will be opened, and never on certificate content.
    """
    return value.encode("utf-8", "backslashreplace").decode("utf-8")


def chain_role(cert: CertInfo) -> str:
    """Role within its own file only (no cross-file chain building)."""
    if cert.is_self_issued:
        return "self_signed"
    if cert.is_ca:
        return "ca"
    return "leaf"


def evidence_confidence(parse_status: str, warnings) -> str:
    if parse_status != "ok":
        return "low"
    return "medium" if warnings else "high"


def blank_record(path: str, filename: str, scan_root: str, fmt: str, discovered_at: str) -> dict:
    record = dict.fromkeys(RECORD_FIELDS)
    record.update(path=safe_text(path), filename=safe_text(filename), scan_root=safe_text(scan_root),
                  format=fmt, discovered_at=discovered_at, warnings=[], extension_mismatch=False,
                  duplicate_in_scan=False, evidence_confidence="low")
    return record


def file_record(path, filename, scan_root, fmt, discovered_at, parse_status, detail,
                access_error=None, extension_mismatch=False) -> dict:
    """A record for a candidate file that produced no certificate."""
    record = blank_record(path, filename, scan_root, fmt, discovered_at)
    record.update(parse_status=parse_status, detail=detail, access_error=access_error,
                  extension_mismatch=extension_mismatch)
    return record


def records_from_file_parse(path: str, filename: str, scan_root: str, parsed: FileParse,
                            discovered_at: dt.datetime, expiring_days: int) -> list[dict]:
    """All records for one parsed file, in certificate order."""
    stamp = iso_utc(discovered_at)
    if not parsed.entries:
        return [file_record(path, filename, scan_root, parsed.format, stamp,
                            parsed.file_status, parsed.detail,
                            extension_mismatch=parsed.extension_mismatch)]
    out = []
    for entry in parsed.entries:
        record = blank_record(path, filename, scan_root, parsed.format, stamp)
        record.update(parse_status=entry.parse_status, detail=entry.detail,
                      chain_index=entry.index, chain_total=parsed.total_certificates,
                      extension_mismatch=parsed.extension_mismatch)
        cert = entry.cert
        if cert is not None:
            validity = assess_validity(cert.not_before, cert.not_after, discovered_at, expiring_days)
            record.update(
                sha256=cert.sha256, serial_hex=cert.serial_hex, subject=cert.subject,
                issuer=cert.issuer, san=[{"type": s.type, "value": s.value} for s in cert.san],
                chain_role=chain_role(cert), key_algorithm=cert.key_algorithm,
                key_size=cert.key_size, key_curve=cert.key_curve,
                signature_algorithm=cert.signature_algorithm,
                not_before=iso_utc(cert.not_before), not_after=iso_utc(cert.not_after),
                days_to_expiry=validity.days_to_expiry, validity_status=validity.status,
                not_yet_valid=validity.not_yet_valid, is_ca=cert.is_ca,
                warnings=list(cert.warnings),
                evidence_confidence=evidence_confidence(entry.parse_status, cert.warnings))
        out.append(record)
    return out
