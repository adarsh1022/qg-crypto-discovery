"""Validation of one filesystem observation record (and of the agent's scan summary).

An allow-list: a record must have exactly the expected fields, each with the expected type, value set
and length. Anything else is rejected with a fixed code. Nothing here is ever stored verbatim except the
named fields, so a field such as `der`, `pem` or `private_key` cannot reach the database.

The accepted shape is agent.observations.RECORD_FIELDS (a contract test keeps the two in step).
Rejection codes are fixed identifiers; they never contain record content.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import os
import re
from dataclasses import dataclass
from typing import Any

from .safety import has_pem_armor, sanitize_text

FS_RECORD_FIELDS = (
    "path", "filename", "scan_root", "format", "discovered_at",
    "sha256", "serial_hex", "subject", "issuer", "san",
    "chain_index", "chain_total", "chain_role",
    "key_algorithm", "key_size", "key_curve", "signature_algorithm",
    "not_before", "not_after", "days_to_expiry", "validity_status", "not_yet_valid",
    "is_ca", "warnings",
    "parse_status", "detail", "access_error", "evidence_confidence",
    "extension_mismatch", "duplicate_in_scan",
    "owning_process",
)

FORMATS = ("pem", "der", "pkcs12", "unknown")
PARSE_STATUSES = ("ok", "malformed", "unsupported", "too_large", "no_certificate", "access_denied", "read_error", "skipped")
CHAIN_ROLES = ("self_signed", "ca", "leaf")
VALIDITY_STATUSES = ("valid", "expiring", "expired")
CONFIDENCES = ("high", "medium", "low")
INTEGRITY_WARNING = "pkcs12_integrity_not_verified"

# certificate facts that identify a certificate; null in every non-"ok" record
CERT_FIELDS = ("sha256", "serial_hex", "subject", "issuer", "san", "chain_role", "key_algorithm", "signature_algorithm",
               "not_before", "not_after", "days_to_expiry", "validity_status", "not_yet_valid")
# columns of the certificates table that are properties of the certificate itself
CERT_COLUMNS = ("sha256", "serial_hex", "subject", "issuer", "san_json", "key_algorithm", "key_size", "key_curve",
                "signature_algorithm", "not_before", "not_after", "is_ca")
OBSERVATION_COLUMNS = ("path", "filename", "scan_root", "format", "discovered_at", "sha256", "chain_index",
                       "chain_total", "chain_role", "parse_status", "detail", "access_error", "evidence_confidence",
                       "extension_mismatch", "warnings_json", "validity_status", "days_to_expiry", "not_yet_valid",
                       "owning_process_json")

MAX_PATH = 33000                 # Windows long paths
MAX_NAME = 1024
MAX_DN = 8192
MAX_SAN_ENTRIES = 500
MAX_SAN_VALUE = 2048
MAX_WARNINGS = 64
MAX_DETAIL = 300
MAX_LISTED_ERRORS = 1000         # agent.fs_scan.MAX_LISTED_ERRORS
DEFAULT_EXPIRING_DAYS = 30       # agent.x509_parse.DEFAULT_EXPIRING_DAYS (a contract test keeps them equal)

# Every pattern is applied with fullmatch(): "$" would also accept a trailing newline, and "\d" would accept
# non-ASCII digits, either of which could pass Python validation and then fail a SQLite CHECK.
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_WARNING = re.compile(r"[a-z0-9_]{1,64}")
_ACCESS_ERROR = re.compile(r"[A-Za-z_]{1,64}:(WinError|errno) -?[0-9]{1,10}")
_SERIAL = re.compile(r"-?[0-9a-f]{1,100}")
_STOP_REASON = re.compile(r"[a-z0-9_]{1,40}")


class RecordRejected(ValueError):
    """The record is not acceptable. `code` is a fixed identifier (never record content)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ValidRecord:
    observation: dict         # values for OBSERVATION_COLUMNS
    certificate: dict | None  # values for CERT_COLUMNS (only for parse_status == "ok")


# ------------------------------------------------------------------ field helpers
def _reject(field: str, why: str = "bad"):
    raise RecordRejected(f"{why}_{field}")


def _text(record: dict, field: str, max_len: int, *, optional: bool = False) -> str | None:
    value = record[field]
    if value is None:
        if optional:
            return None
        _reject(field)
    if not isinstance(value, str) or (not value and field in ("path", "filename", "scan_root")):
        _reject(field)
    text = sanitize_text(value)
    if len(text) > max_len:
        _reject(field, "too_long")
    if has_pem_armor(text):
        _reject(field, "pem_armor_in")
    return text


def _enum(record: dict, field: str, allowed: tuple[str, ...], *, optional: bool = False) -> str | None:
    value = record[field]
    if value is None and optional:
        return None
    if not isinstance(value, str) or value not in allowed:
        _reject(field)
    return value


def _int(record: dict, field: str, *, low: int, high: int = 2**31 - 1, optional: bool = False) -> int | None:
    value = record[field]
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        _reject(field)
    return value


def _bool(record: dict, field: str, *, optional: bool = False) -> bool | None:
    value = record[field]
    if value is None and optional:
        return None
    if not isinstance(value, bool):
        _reject(field)
    return value


def _timestamp(record: dict, field: str) -> str:
    value = record[field]
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        _reject(field)
    try:
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _reject(field)
    return value


def _san(value: Any) -> str:
    if not isinstance(value, list) or len(value) > MAX_SAN_ENTRIES:
        _reject("san")
    entries = []
    for item in value:
        if not (isinstance(item, dict) and set(item) == {"type", "value"}
                and isinstance(item["type"], str) and isinstance(item["value"], str)):
            _reject("san")
        kind, text = sanitize_text(item["type"]), sanitize_text(item["value"])
        if len(kind) > 64 or len(text) > MAX_SAN_VALUE:
            _reject("san", "too_long")
        if has_pem_armor(kind) or has_pem_armor(text):
            _reject("san", "pem_armor_in")
        entries.append({"type": kind, "value": text})
    return canonical_json(entries)


def _warnings(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_WARNINGS:
        _reject("warnings")
    for item in value:
        if not isinstance(item, str) or not _WARNING.fullmatch(item):
            _reject("warnings")
    return list(value)


def canonical_json(value: Any) -> str:
    """Deterministic JSON (so stored values can be compared); ASCII-only, which also keeps surrogates harmless.

    allow_nan=False: NaN and Infinity are not valid JSON (SQLite's json_valid() refuses them), so they raise
    ValueError here instead of failing a CHECK constraint later.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


# ------------------------------------------------------------------ derived-claim consistency
def _assess(not_before: dt.datetime, not_after: dt.datetime, now: dt.datetime, expiring_days: int) -> tuple[str, int, bool]:
    """(validity_status, days_to_expiry, not_yet_valid): the same rules as agent.x509_parse.assess_validity."""
    days = math.floor((not_after - now).total_seconds() / 86400)
    if now > not_after:
        status = "expired"
    elif days <= expiring_days:
        status = "expiring"
    else:
        status = "valid"
    return status, days, now < not_before


def assess_at(not_before: str, not_after: str, now: dt.datetime, expiring_days: int) -> tuple[str, int, bool]:
    """(validity_status, days_to_expiry, not_yet_valid) of a stored certificate at `now`, by the agent's own rules.

    `not_before` / `not_after` are the stored 'YYYY-MM-DDTHH:MM:SSZ' texts; `now` must be timezone-aware.
    """
    if now.tzinfo is None:
        raise ValueError("assess_at needs a timezone-aware datetime")
    parse = lambda text: dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)   # noqa: E731
    return _assess(parse(not_before), parse(not_after), now, expiring_days)


def possible_validity(not_before: str, not_after: str, discovered_at: str, expiring_days: int) -> set[tuple[str, int, bool]]:
    """Every (status, days, not_yet_valid) an honest agent could have reported for these three timestamps.

    The agent classifies at its full-precision clock reading, but discovered_at is truncated to whole seconds, so
    the real reading lies in [discovered_at, discovered_at + 1s). Each of the three values changes at instants where
    the remaining time is a whole number of days (or at not_before, a whole second), so at most one change can fall
    inside that second and the two ends of the interval give every possible answer.
    """
    parse = lambda text: dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)   # noqa: E731
    before, after, low = parse(not_before), parse(not_after), parse(discovered_at)
    high = low + dt.timedelta(microseconds=999_999)
    return {_assess(before, after, low, expiring_days), _assess(before, after, high, expiring_days)}


def _validity_mismatch_code(claimed: tuple[str, int, bool], possible: set[tuple[str, int, bool]]) -> str:
    if claimed[0] not in {p[0] for p in possible}:
        return "validity_status_mismatch"
    if claimed[1] not in {p[1] for p in possible}:
        return "days_to_expiry_mismatch"
    if claimed[2] not in {p[2] for p in possible}:
        return "not_yet_valid_mismatch"
    return "validity_facts_inconsistent"          # each value is possible on its own, but not together


def expiring_days_with_source(config: Any) -> tuple[int, str]:
    """(threshold, source): the 'expiring' threshold the run asked the agent to use, and whether it came from the run's
    configuration ("run_config") or is the agent's own default ("default", also when the stored value is unusable)."""
    value = config.get("expiring_days") if isinstance(config, dict) else None
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10**7:
        return value, "run_config"
    return DEFAULT_EXPIRING_DAYS, "default"


def expiring_days_from_config(config: Any) -> int:
    """The 'expiring' threshold the run asked the agent to use (its own default when the config does not say)."""
    return expiring_days_with_source(config)[0]


# ------------------------------------------------------------------ record validation
def validate_fs_record(record: Any, *, expiring_days: int = DEFAULT_EXPIRING_DAYS) -> ValidRecord:
    """Return the normalised values to store, or raise RecordRejected.

    Besides shape and vocabulary, an "ok" record's derived claims must agree with each other and with the agent's
    own rules (a cryptographic inventory that reports a wrong posture is worse than one that reports less):
      validity_status, days_to_expiry, not_yet_valid  <-  not_before, not_after, discovered_at, expiring_days
      evidence_confidence                              <-  warnings (medium when there are any, otherwise high)
    """
    if not isinstance(record, dict):
        raise RecordRejected("not_an_object")
    keys = set(record)
    if not all(isinstance(k, str) for k in keys):
        raise RecordRejected("unknown_field")
    if keys - set(FS_RECORD_FIELDS):
        raise RecordRejected("unknown_field")          # e.g. der / pem / private_key: never accepted
    if set(FS_RECORD_FIELDS) - keys:
        raise RecordRejected("missing_field")

    fmt = _enum(record, "format", FORMATS)
    status = _enum(record, "parse_status", PARSE_STATUSES)
    confidence = _enum(record, "evidence_confidence", CONFIDENCES)
    warnings = _warnings(record["warnings"])
    chain_index = _int(record, "chain_index", low=0, optional=True)
    chain_total = _int(record, "chain_total", low=0, optional=True)
    _bool(record, "duplicate_in_scan")                  # the agent's own claim; the backend recomputes duplicates
    if record["owning_process"] is not None:
        _reject("owning_process")                       # reserved: Phase 1 never attributes a process

    observation = dict(
        path=_text(record, "path", MAX_PATH), filename=_text(record, "filename", MAX_NAME),
        scan_root=_text(record, "scan_root", MAX_PATH), format=fmt,
        discovered_at=_timestamp(record, "discovered_at"),
        chain_index=chain_index, chain_total=chain_total, parse_status=status,
        detail=_text(record, "detail", MAX_DETAIL, optional=True),
        access_error=None, evidence_confidence=confidence,
        extension_mismatch=int(_bool(record, "extension_mismatch")),
        warnings_json=canonical_json(warnings), owning_process_json=None,
    )
    access_error = record["access_error"]
    if access_error is not None:
        if not isinstance(access_error, str) or not _ACCESS_ERROR.fullmatch(access_error):
            _reject("access_error")
        observation["access_error"] = access_error

    if fmt == "pkcs12" and chain_index is not None:
        raise RecordRejected("pkcs12_chain_index")       # PFX order is not chain order (Phase 1 decision)
    # Mirrors the CHECK in fs_observations, which uses a SUBSTRING test (instr) on the warnings JSON: any warning
    # containing the integrity marker, not only the exact one, must not coexist with high confidence.
    if confidence == "high" and any(INTEGRITY_WARNING in item for item in warnings):
        raise RecordRejected("integrity_warning_with_high_confidence")

    if status != "ok":
        if any(record[f] is not None for f in CERT_FIELDS) or any(record[f] is not None for f in (
                "key_size", "key_curve", "is_ca")):
            raise RecordRejected("failure_with_certificate_fields")
        if confidence != "low":
            raise RecordRejected("failure_confidence_not_low")
        observation.update(sha256=None, chain_role=None, validity_status=None, days_to_expiry=None, not_yet_valid=None)
        return ValidRecord(observation, None)

    sha256 = record["sha256"]
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        _reject("sha256")
    serial = record["serial_hex"]
    if not isinstance(serial, str) or not _SERIAL.fullmatch(serial):
        _reject("serial_hex")
    is_ca = _bool(record, "is_ca", optional=True)
    not_before, not_after = _timestamp(record, "not_before"), _timestamp(record, "not_after")
    validity = _enum(record, "validity_status", VALIDITY_STATUSES)
    days = _int(record, "days_to_expiry", low=-10**7, high=10**7)
    not_yet_valid = _bool(record, "not_yet_valid")
    role = _enum(record, "chain_role", CHAIN_ROLES)

    possible = possible_validity(not_before, not_after, observation["discovered_at"], expiring_days)
    if (validity, days, not_yet_valid) not in possible:
        raise RecordRejected(_validity_mismatch_code((validity, days, not_yet_valid), possible))
    if confidence != ("medium" if warnings else "high"):
        raise RecordRejected("confidence_warnings_mismatch")

    certificate = dict(
        sha256=sha256, serial_hex=serial, subject=_text(record, "subject", MAX_DN), issuer=_text(record, "issuer", MAX_DN),
        san_json=_san(record["san"]), key_algorithm=_text(record, "key_algorithm", 256),
        key_size=_int(record, "key_size", low=1, high=10**6, optional=True),
        key_curve=_text(record, "key_curve", 256, optional=True),
        signature_algorithm=_text(record, "signature_algorithm", 256),
        not_before=not_before, not_after=not_after, is_ca=None if is_ca is None else int(is_ca),
    )
    observation.update(sha256=sha256, chain_role=role, validity_status=validity, days_to_expiry=days,
                       not_yet_valid=int(not_yet_valid))
    return ValidRecord(observation, certificate)


# ------------------------------------------------------------------ the agent's scan summary
ROOT_SCANNED_STATUSES = ("scanned", "partial")           # the agent actually walked these
ROOT_NEUTRAL_STATUSES = ("overlap",)                     # deliberately skipped: covered by another root
ERROR_KINDS = ("root", "listdir", "stat", "read")
DIRECTORY_LEVEL_ERROR_KINDS = ("root", "listdir", "stat")   # not accompanied by a record; "read" errors are


MAX_SUMMARY_JSON = 256 * 1024     # bound on runs.agent_summary_json
MAX_ROOTS = 200
MAX_STORED_ROOT = 1024            # roots are shortened in the stored copy only; reconciliation uses the full text
MAX_SUMMARY_NODES = 200_000       # bound on the structure walked when looking for non-finite numbers
MAX_COUNT = 10**12
MAX_ELAPSED_SECONDS = 10**9


@dataclass(frozen=True)
class SummaryFacts:
    """What the backend uses from Scan.summary. Claims, to be cross-checked against persisted evidence."""
    stop_reason: str | None
    records: int | None
    errors_total: int | None
    bundles_truncated: int
    roots_not_scanned: int
    roots_walked: int
    reported_roots: tuple[str, ...]              # every root the agent reported, sanitised, whatever its status
    errors: tuple[tuple[str, str, str], ...]     # (path, kind, code), already validated and sanitised
    invalid_errors: int
    stored: dict                                 # sanitised copy for runs.agent_summary_json (without the error list)


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_COUNT else None


def _unsafe_numbers(value: Any) -> bool:
    """True if a nested structure holds a NaN/Infinity float (checked with math.isfinite), or is implausibly large.

    Iterative and node-limited, so a hostile or self-referencing structure cannot hang or overflow the stack.
    """
    stack, seen = [value], 0
    while stack:
        item = stack.pop()
        seen += 1
        if seen > MAX_SUMMARY_NODES:
            return True
        if isinstance(item, float):
            if not math.isfinite(item):
                return True
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return False


def parse_summary(summary: Any) -> SummaryFacts | None:
    """Validate Scan.summary; None if it cannot be used at all (the caller then treats the run as unverified).

    Rejected as a whole: wrong shape, any non-finite number, too many roots, or a stored form larger than
    MAX_SUMMARY_JSON. Rejection can only make a run look worse (stop reason unknown), never better.
    """
    if not isinstance(summary, dict) or _unsafe_numbers(summary):
        return None
    stop = summary.get("stop_reason")
    if stop is not None and not (isinstance(stop, str) and _STOP_REASON.fullmatch(stop)):
        return None
    roots = summary.get("roots")
    if not isinstance(roots, list) or len(roots) > MAX_ROOTS or not all(
            isinstance(r, dict) and isinstance(r.get("root"), str) and isinstance(r.get("status"), str) for r in roots):
        return None
    raw_errors = summary.get("errors", [])
    if not isinstance(raw_errors, list):
        return None
    errors, invalid = [], 0
    for item in raw_errors:
        if (isinstance(item, dict) and isinstance(item.get("path"), str) and item.get("kind") in ERROR_KINDS
                and isinstance(item.get("code"), str) and _ACCESS_ERROR.fullmatch(item["code"])):
            path = sanitize_text(item["path"])
            if len(path) <= MAX_PATH and not has_pem_armor(path) and len(errors) < MAX_LISTED_ERRORS:
                errors.append((path, item["kind"], item["code"]))
                continue
        invalid += 1

    statuses = [sanitize_text(r["status"])[:40] for r in roots]
    reported = tuple(sanitize_text(r["root"]) for r in roots)
    walked = sum(1 for st in statuses if st in ROOT_SCANNED_STATUSES)
    not_scanned = sum(1 for st in statuses if st not in ROOT_SCANNED_STATUSES and st not in ROOT_NEUTRAL_STATUSES)
    elapsed = summary.get("elapsed_seconds")
    stored = {"stop_reason": stop, "complete": summary.get("complete") if isinstance(summary.get("complete"), bool) else None,
              "roots": [{"root": root[:MAX_STORED_ROOT], "status": st} for root, st in zip(reported, statuses)],
              "elapsed_seconds": elapsed if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool)
              and 0 <= elapsed <= MAX_ELAPSED_SECONDS else None}
    for key in ("directories_visited", "entries_visited", "candidate_files", "files_read", "records",
                "unique_certificates", "duplicate_observations", "bundles_truncated", "errors_total"):
        stored[key] = _count(summary.get(key))
    for key in ("records_by_status", "skipped"):
        value = summary.get(key)
        stored[key] = {sanitize_text(str(k))[:64]: v for k, v in value.items() if _count(v) is not None}             if isinstance(value, dict) and len(value) <= 64 else None
    try:
        if len(canonical_json(stored)) > MAX_SUMMARY_JSON:
            return None
    except ValueError:
        return None
    return SummaryFacts(stop_reason=stop, records=stored["records"], errors_total=stored["errors_total"],
                        bundles_truncated=stored["bundles_truncated"] or 0, roots_not_scanned=not_scanned,
                        roots_walked=walked, reported_roots=reported, errors=tuple(errors), invalid_errors=invalid,
                        stored=stored)


# ------------------------------------------------------------------ requested roots vs reported roots
def normalize_root(root: str) -> str:
    """Same normalisation Phase 1 applies to configured roots (os.path.normpath), made case-insensitive on Windows."""
    return os.path.normcase(os.path.normpath(root))


def requested_roots(config: Any) -> tuple[str, ...] | None:
    """Explicit roots named in a run's configuration, or None when it names none (the agent's defaults then apply)."""
    roots = config.get("roots") if isinstance(config, dict) else None
    if not isinstance(roots, (list, tuple)) or not roots or not all(isinstance(r, str) and r for r in roots):
        return None
    return tuple(roots)


def unreported_roots(requested: tuple[str, ...], reported: tuple[str, ...]) -> int:
    """How many distinct requested roots the agent's summary does not mention at all (any status counts as mentioned).

    Roots are compared as sets after normalisation, so a root listed twice in the request is one root, and a root
    the agent reported as 'overlap' (covered by another root) is mentioned. Statuses are judged elsewhere.
    """
    mentioned = {normalize_root(r) for r in reported}
    return len({normalize_root(r) for r in requested} - mentioned)
