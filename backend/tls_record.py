"""Validation of one TLS observation record and of the agent's TLS scan summary.

WHAT A TLS RECORD IS. One record is ONE ACTIVE PROBE ATTEMPT by the agent against a listener on this machine. It is not a
passively observed connection and not other programs' network traffic. The validator enforces that on every record:

  * direction is "unknown" (a synthetic probe is neither inbound nor outbound traffic); local_* / remote_* are never sent;
  * warnings contain the markers "active_probe" and "packet_counts_unavailable"; event_count is 1 (one probe attempt),
    packet_count is 0 (packet counts are unavailable: nothing is captured) and event_counts.probe_attempts is 1;
  * the source is the probe's own socket and the destination is the listener, both literal IP addresses.

An allow-list, like fs_record: a record must have exactly the expected fields, each of the expected type, vocabulary and
length. Anything else (a `der`, `pem` or `private_key` field, PEM armour inside any text, ...) is rejected with a fixed code that
never contains record content. Certificates arrive as parsed FACTS; raw certificate bytes are never accepted.

CONSISTENCY the database does not enforce (checked here):
  * a version and a cipher are present exactly when the handshake completed; a failed, incomplete, alert or unknown outcome
    never carries a version, a cipher or a certificate (nothing is invented for an inconclusive probe);
  * cert_visibility is "visible" exactly when peer certificates are present ("encrypted_tls13" describes passive capture and
    is refused);
  * process attribution matches the pid / name / path fields; confidence follows one rule (see agent.tls_probe).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from .fs_record import (MAX_DN, MAX_ELAPSED_SECONDS, MAX_PATH, MAX_SUMMARY_JSON, RecordRejected, ValidRecord, _SERIAL, _SHA256,
                        _STOP_REASON, _bool, _count, _enum, _int, _reject, _san, _text, _timestamp, _unsafe_numbers, _warnings,
                        canonical_json)

TLS_RECORD_FIELDS = (
    "observed_at", "direction", "transport", "src_ip", "src_port", "dst_ip", "dst_port", "handshake_outcome", "sni",
    "tls_version", "cipher_suite", "cert_visibility", "pid", "process_name", "exe_path", "process_attribution",
    "event_count", "packet_count", "event_counts", "evidence_confidence", "warnings", "peer_certificates",
)
CERT_FACT_FIELDS = ("sha256", "serial_hex", "subject", "issuer", "san", "key_algorithm", "key_size", "key_curve",
                    "signature_algorithm", "not_before", "not_after", "is_ca")
OBSERVATION_COLUMNS = (
    "observed_at", "direction", "transport", "src_ip", "src_port", "dst_ip", "dst_port", "handshake_outcome", "sni",
    "tls_version", "cipher_suite", "cert_visibility", "pid", "process_name", "exe_path", "process_attribution",
    "event_count", "packet_count", "event_counts_json", "evidence_confidence", "warnings_json",
)

OUTCOMES = ("completed", "failed", "alert", "incomplete", "unknown")
VERSIONS = ("SSL3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3")
VISIBILITIES = ("visible", "not_observed")                       # "encrypted_tls13" is passive-capture vocabulary: refused
ATTRIBUTIONS = ("attributed", "not_found", "unavailable")
CONFIDENCES = ("high", "medium", "low")
MARKER_WARNINGS = ("active_probe", "packet_counts_unavailable")
EVENT_COUNT_KEYS = ("probe_attempts", "handshake_completed")
MAX_PEER_CERTIFICATES = 10
MAX_CIPHER = 128
MAX_PROCESS_NAME = 1024
ERROR_KINDS = ("enumerate", "probe")                              # kinds of agent-reported TLS scan errors

_CIPHER = re.compile(r"[A-Za-z0-9_\-]{1,128}")
_ERROR_CODE = re.compile(r"[a-z0-9_]{1,64}")


@dataclass(frozen=True)
class ValidTlsRecord:
    observation: dict                  # values for OBSERVATION_COLUMNS
    certificates: tuple[dict, ...]     # values for CERT_COLUMNS, leaf first (one per peer position)


def derive_confidence(outcome: str, peer_count: int, warnings: list[str]) -> str:
    """The one confidence rule; agent.tls_probe.derive_confidence is its twin and a contract test keeps them equal."""
    if outcome != "completed":
        return "low"
    if peer_count == 0:
        return "medium"
    return "medium" if any(w not in MARKER_WARNINGS for w in warnings) else "high"


def _address(record: dict, field: str) -> str:
    value = record[field]
    if not isinstance(value, str) or not value or "%" in value:
        _reject(field)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        _reject(field)
    if (address.version == 6 and address.ipv4_mapped is not None) or address.is_unspecified or address.is_multicast \
            or address.is_link_local:
        _reject(field)
    return str(address)


def _certificate_facts(item: Any) -> dict:
    if not isinstance(item, dict) or set(item) != set(CERT_FACT_FIELDS):
        _reject("peer_certificates")
    sha256, serial = item["sha256"], item["serial_hex"]
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        _reject("sha256")
    if not isinstance(serial, str) or not _SERIAL.fullmatch(serial):
        _reject("serial_hex")
    is_ca = _bool(item, "is_ca", optional=True)
    return dict(
        sha256=sha256, serial_hex=serial, subject=_text(item, "subject", MAX_DN), issuer=_text(item, "issuer", MAX_DN),
        san_json=_san(item["san"]), key_algorithm=_text(item, "key_algorithm", 256),
        key_size=_int(item, "key_size", low=1, high=10**6, optional=True), key_curve=_text(item, "key_curve", 256, optional=True),
        signature_algorithm=_text(item, "signature_algorithm", 256),
        not_before=_timestamp(item, "not_before"), not_after=_timestamp(item, "not_after"),
        is_ca=None if is_ca is None else int(is_ca))


def validate_tls_record(record: Any) -> ValidTlsRecord:
    """The normalised values to store, or RecordRejected with a fixed code."""
    if not isinstance(record, dict):
        raise RecordRejected("not_an_object")
    keys = set(record)
    if not all(isinstance(k, str) for k in keys) or keys - set(TLS_RECORD_FIELDS):
        raise RecordRejected("unknown_field")             # e.g. der / pem / private_key / local_ip: never accepted
    if set(TLS_RECORD_FIELDS) - keys:
        raise RecordRejected("missing_field")

    if record["direction"] != "unknown":
        _reject("direction")
    if record["transport"] != "tcp":
        _reject("transport")
    outcome = _enum(record, "handshake_outcome", OUTCOMES)
    if record["sni"] is not None:
        _reject("sni")                                    # the probe uses an IP literal and sends no SNI
    version = _enum(record, "tls_version", VERSIONS, optional=True)
    cipher = _text(record, "cipher_suite", MAX_CIPHER, optional=True)
    if cipher is not None and not _CIPHER.fullmatch(cipher):
        _reject("cipher_suite")
    visibility = _enum(record, "cert_visibility", VISIBILITIES)
    confidence = _enum(record, "evidence_confidence", CONFIDENCES)
    src_port = _int(record, "src_port", low=1, high=65535)
    dst_port = _int(record, "dst_port", low=1, high=65535)

    completed = outcome == "completed"
    if completed != (version is not None) or completed != (cipher is not None):
        raise RecordRejected("handshake_details_mismatch")

    peers_raw = record["peer_certificates"]
    if not isinstance(peers_raw, list) or len(peers_raw) > MAX_PEER_CERTIFICATES:
        _reject("peer_certificates")
    if peers_raw and not completed:
        raise RecordRejected("certificate_without_completed_handshake")
    certificates = tuple(_certificate_facts(item) for item in peers_raw)
    if (visibility == "visible") != bool(certificates):
        raise RecordRejected("cert_visibility_mismatch")

    pid = _int(record, "pid", low=0, optional=True)
    name = _text(record, "process_name", MAX_PROCESS_NAME, optional=True)
    exe = _text(record, "exe_path", MAX_PATH, optional=True)
    attribution = _enum(record, "process_attribution", ATTRIBUTIONS)
    expected = {"attributed": (True, True, True), "not_found": (True, False, False), "unavailable": (False, False, False)}[attribution]
    if (pid is not None, name is not None, exe is not None) != expected:
        raise RecordRejected("process_attribution_mismatch")

    if _int(record, "event_count", low=0, high=1000) != 1:
        _reject("event_count")
    if _int(record, "packet_count", low=0, high=10**12) != 0:
        _reject("packet_count")
    counts = record["event_counts"]
    if not isinstance(counts, dict) or set(counts) != set(EVENT_COUNT_KEYS) or counts["probe_attempts"] != 1 \
            or isinstance(counts["probe_attempts"], bool) or counts["handshake_completed"] != int(completed) \
            or isinstance(counts["handshake_completed"], bool):
        _reject("event_counts")

    warnings = _warnings(record["warnings"])
    if len(set(warnings)) != len(warnings):
        _reject("warnings")
    if any(marker not in warnings for marker in MARKER_WARNINGS):
        raise RecordRejected("missing_probe_markers")
    if confidence != derive_confidence(outcome, len(certificates), warnings):
        raise RecordRejected("confidence_mismatch")

    observation = dict(
        observed_at=_timestamp(record, "observed_at"), direction="unknown", transport="tcp",
        src_ip=_address(record, "src_ip"), src_port=src_port, dst_ip=_address(record, "dst_ip"), dst_port=dst_port,
        handshake_outcome=outcome, sni=None, tls_version=version, cipher_suite=cipher, cert_visibility=visibility,
        pid=pid, process_name=name, exe_path=exe, process_attribution=attribution, event_count=1, packet_count=0,
        event_counts_json=canonical_json({"handshake_completed": int(completed), "probe_attempts": 1}),
        evidence_confidence=confidence, warnings_json=canonical_json(warnings))
    return ValidTlsRecord(observation, certificates)


def as_fs_valid_record(valid: ValidTlsRecord, certificate: dict) -> ValidRecord:
    """The shape the shared certificate-catalog upsert expects (it reads the certificate and the observation time)."""
    return ValidRecord({"discovered_at": valid.observation["observed_at"]}, certificate)


# ------------------------------------------------------------------ the agent's TLS scan summary
ENUMERATIONS = ("ok", "failed")
COUNT_KEYS = ("listeners_found", "port_filtered", "policy_skipped", "targets_planned", "targets_probed", "records",
              "handshakes_completed")
MAX_LISTED_ERRORS = 1000


@dataclass(frozen=True)
class TlsSummaryFacts:
    """What the backend uses from TlsScan.summary. Claims, cross-checked against persisted evidence."""
    stop_reason: str | None
    enumeration: str
    records: int | None
    handshakes_completed: int | None
    errors_total: int | None
    errors: tuple[tuple[str, str], ...]          # (kind, code), already validated
    invalid_errors: int
    stored: dict                                 # sanitised copy for runs.agent_summary_json (without the error list)


def parse_tls_summary(summary: Any) -> TlsSummaryFacts | None:
    """Validate TlsScan.summary; None if it cannot be used at all (the run is then treated as unverified)."""
    if not isinstance(summary, dict) or _unsafe_numbers(summary):
        return None
    stop = summary.get("stop_reason")
    if stop is not None and not (isinstance(stop, str) and _STOP_REASON.fullmatch(stop)):
        return None
    enumeration = summary.get("enumeration")
    if enumeration not in ENUMERATIONS:
        return None
    raw_errors = summary.get("errors", [])
    if not isinstance(raw_errors, list):
        return None
    errors, invalid = [], 0
    for item in raw_errors:
        if (isinstance(item, dict) and set(item) == {"kind", "code"} and item["kind"] in ERROR_KINDS
                and isinstance(item["code"], str) and _ERROR_CODE.fullmatch(item["code"]) and len(errors) < MAX_LISTED_ERRORS):
            errors.append((item["kind"], item["code"]))
        else:
            invalid += 1
    stored: dict = {"stop_reason": stop, "enumeration": enumeration,
                    "complete": summary.get("complete") if isinstance(summary.get("complete"), bool) else None,
                    "targets_truncated": summary.get("targets_truncated") if isinstance(summary.get("targets_truncated"), bool) else None}
    for key in COUNT_KEYS + ("errors_total",):
        stored[key] = _count(summary.get(key))
    outcomes = summary.get("records_by_outcome")
    stored["records_by_outcome"] = ({k: v for k, v in outcomes.items() if k in OUTCOMES and _count(v) is not None}
                                    if isinstance(outcomes, dict) and len(outcomes) <= 16 else None)
    elapsed = summary.get("elapsed_seconds")
    stored["elapsed_seconds"] = (elapsed if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool)
                                 and 0 <= elapsed <= MAX_ELAPSED_SECONDS else None)
    try:
        if len(canonical_json(stored)) > MAX_SUMMARY_JSON:
            return None
    except ValueError:
        return None
    return TlsSummaryFacts(stop_reason=stop, enumeration=enumeration, records=stored["records"],
                           handshakes_completed=stored["handshakes_completed"], errors_total=stored["errors_total"],
                           errors=tuple(errors), invalid_errors=invalid, stored=stored)

