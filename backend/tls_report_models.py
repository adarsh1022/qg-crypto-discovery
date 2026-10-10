"""Response models for the TLS report endpoints (pydantic v2): an ALLOW-LIST of what may leave the service.

Same principle as report_models: the report functions return plain dictionaries that can carry more than the API publishes
(the internal row id, columns that are always empty for a probe). Passing them through these models drops everything not listed,
so a field only becomes public by being added here on purpose. Nothing here can hold raw certificate bytes, PEM/DER, private keys,
application data, lease or token material, and nothing is built from request content.

The rows describe ACTIVE PROBE ATTEMPTS against listeners on this machine, not observed traffic. `direction` is always "unknown",
`event_count` is 1 and `packet_count` is 0 (packet counts are unavailable: nothing is captured). `local_*` / `remote_*` columns are
always empty for probes and are not published.
"""
from __future__ import annotations

from pydantic import BaseModel

from .report_models import ExpiringDays, FrontierScope, Ranked, ValidityCounts


class TlsSummaryRun(BaseModel):
    run_id: str
    run_number: int
    type: str
    status: str
    final: bool
    started_at: str | None
    finished_at: str | None


class TlsTotals(BaseModel):
    probe_attempts: int
    handshakes_completed: int          # the only TLS findings
    not_completed: int                 # failed, incomplete, alert or unknown probes: NOT findings
    endpoints: int
    certificates_presented: int
    leaf_certificates: int


class CipherItem(BaseModel):
    cipher_suite: str | None
    handshakes: int


class OtherCiphers(BaseModel):
    groups: int
    handshakes: int


class TlsErrorCounts(BaseModel):
    total: int
    enumerate: int
    probe: int


class TlsIssueCounts(BaseModel):
    errors: TlsErrorCounts
    rejected: int
    seq_conflicts: int


class TlsCertificateValidity(BaseModel):
    expiring_days: ExpiringDays
    now: ValidityCounts                # per unique leaf certificate, judged at the request time; trust is not evaluated


class TlsScan(BaseModel):
    """The agent's own scan facts as validated and stored at finalization (claims, not evidence)."""
    stop_reason: str | None
    enumeration: str | None            # "ok" or "failed": zero eligible listeners is distinguishable from a failed enumeration
    listeners_found: int | None
    port_filtered: int | None
    policy_skipped: int | None
    targets_planned: int | None
    targets_probed: int | None
    targets_truncated: bool | None


class TlsSummary(BaseModel):
    run: TlsSummaryRun
    as_of: str
    frontier: int
    frontier_scope: FrontierScope
    totals: TlsTotals
    outcomes: dict[str, int]
    tls_versions: dict[str, int]
    cipher_suites: Ranked[CipherItem, OtherCiphers]
    process_attribution: dict[str, int]
    certificate_validity: TlsCertificateValidity
    issues: TlsIssueCounts
    scan: TlsScan | None


class PeerCertificate(BaseModel):
    position: int                      # 0 = leaf
    sha256: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    key_algorithm: str
    key_size: int | None
    key_curve: str | None
    signature_algorithm: str
    is_ca: bool | None


class TlsObservation(BaseModel):
    seq: int
    observed_at: str
    direction: str                     # always "unknown" for active probes
    transport: str
    src_ip: str                        # the probe's own socket
    src_port: int
    dst_ip: str                        # the listener that was probed
    dst_port: int
    handshake_outcome: str
    sni: str | None
    tls_version: str | None
    cipher_suite: str | None
    cert_visibility: str
    pid: int | None
    process_name: str | None
    exe_path: str | None
    process_attribution: str
    event_count: int                   # 1 = one probe attempt
    packet_count: int                  # 0 = packet counts are unavailable (no packet capture)
    event_counts: dict[str, int]
    evidence_confidence: str
    warnings: list[str]
    peer_certificates: list[PeerCertificate]


class TlsObservationPage(BaseModel):
    items: list[TlsObservation]
    total: int
    limit: int
    offset: int
    frontier: int
