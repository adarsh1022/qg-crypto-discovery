"""Response models for the report endpoints (pydantic v2): an ALLOW-LIST of what may leave the service.

The report functions return plain dictionaries that can carry more than the API publishes (internal ids, flags, counts
kept for other purposes). Passing them through these models drops everything not listed here, so a field only becomes
public by being added to a model on purpose. No model contains lease, token, hash-of-token, DER, PEM or key material, and
nothing here is ever built from request content.
"""
from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")
O = TypeVar("O")


# ------------------------------------------------------------------ /api/meta
class Meta(BaseModel):
    data_origin: str | None
    schema_version: int
    server_time: str


# ------------------------------------------------------------------ runs (statistics and dashboard)
class RunBrief(BaseModel):
    run_id: str
    run_number: int
    type: str
    status: str
    started_at: str | None
    duration_ms: int | None
    record_count: int
    finding_count: int


class TypeStatusCount(BaseModel):
    type: str
    status: str
    count: int


class RunStatistics(BaseModel):
    by_type_status: list[TypeStatusCount]
    series: list[RunBrief]


# ------------------------------------------------------------------ per-run summary
class SummaryRun(BaseModel):
    run_id: str
    run_number: int
    type: str
    status: str
    final: bool
    started_at: str | None
    finished_at: str | None


class ExpiringDays(BaseModel):
    value: int
    source: str


class FrontierScope(BaseModel):
    frozen: list[str]
    live: list[str]


class Duplicates(BaseModel):
    total: int
    within_file: int
    across_files: int


class Totals(BaseModel):
    records: int
    sightings: int
    unique_certificates: int
    duplicate_observations: Duplicates
    parse_failures: int
    no_certificate: int
    skipped: int


class ValidityCounts(BaseModel):
    valid: int
    expiring: int
    expired: int
    not_yet_valid: int


class ValidityNow(BaseModel):
    unique: ValidityCounts
    sightings: ValidityCounts


class Validity(BaseModel):
    at_discovery: ValidityCounts
    now: ValidityNow


class BucketsNow(BaseModel):
    unique: dict[str, int]
    sightings: dict[str, int]


class ExpiryBuckets(BaseModel):
    definitions: list[str]
    at_discovery: dict[str, int]
    now: BucketsNow


class Ranked(BaseModel, Generic[T, O]):
    top: list[T]
    other: O | None
    total_groups: int
    limit: int


class AlgorithmItem(BaseModel):
    key_algorithm: str | None
    key_size: int | None
    key_curve: str | None
    unique: int
    sightings: int


class SignatureItem(BaseModel):
    signature_algorithm: str | None
    unique: int
    sightings: int


class IssuerItem(BaseModel):
    issuer: str | None
    unique: int
    sightings: int


class RootItem(BaseModel):
    scan_root: str
    observations: int
    sightings: int
    unique: int


class DirectoryItem(BaseModel):
    directory: str
    sightings: int
    unique: int


class OtherCertificates(BaseModel):
    groups: int
    unique: int
    sightings: int


class OtherRoots(BaseModel):
    groups: int
    observations: int
    sightings: int


class OtherDirectories(BaseModel):
    groups: int
    sightings: int


class Locations(BaseModel):
    scan_roots: Ranked[RootItem, OtherRoots]
    directories: Ranked[DirectoryItem, OtherDirectories]


class ErrorCounts(BaseModel):
    total: int
    file_errors: int
    directory_errors: int
    unresolved_read_errors: int


class IssueCounts(BaseModel):
    errors: ErrorCounts
    rejected: int
    seq_conflicts: int


class Summary(BaseModel):
    run: SummaryRun
    as_of: str
    frontier: int
    frontier_scope: FrontierScope
    expiring_days: ExpiringDays
    totals: Totals
    parse_status: dict[str, int]
    formats: dict[str, int]
    validity: Validity
    expiry_buckets: ExpiryBuckets
    algorithms: Ranked[AlgorithmItem, OtherCertificates]
    signature_algorithms: Ranked[SignatureItem, OtherCertificates]
    issuers: Ranked[IssuerItem, OtherCertificates]
    locations: Locations
    issues: IssueCounts


class Dashboard(BaseModel):
    latest_run: RunBrief | None
    latest_terminal_fs_run: RunBrief | None
    summary: Summary | None
    runs_by_status: dict[str, int]
    recent_runs: list[RunBrief]


# ------------------------------------------------------------------ inventory
class SanEntry(BaseModel):
    type: str
    value: str


class Sighting(BaseModel):
    seq: int
    entry_ordinal: int
    path: str
    filename: str
    scan_root: str
    format: str
    discovered_at: str
    sha256: str | None
    chain_index: int | None
    chain_total: int | None
    chain_role: str | None
    parse_status: str
    detail: str | None
    access_error: str | None
    evidence_confidence: str
    validity_status: str | None
    days_to_expiry: int | None
    duplicate_kind: str
    serial_hex: str | None
    subject: str | None
    issuer: str | None
    san: list[SanEntry] | None
    key_algorithm: str | None
    key_size: int | None
    key_curve: str | None
    signature_algorithm: str | None
    not_before: str | None
    not_after: str | None
    warnings: list[str]
    owning_process: None = None             # owner-process attribution is not implemented for filesystem scans


class SightingPage(BaseModel):
    items: list[Sighting]
    total: int
    limit: int
    offset: int
    frontier: int


class UniqueCertificate(BaseModel):
    sha256: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    key_algorithm: str
    key_size: int | None
    key_curve: str | None
    signature_algorithm: str
    sightings: int
    paths: int


class UniqueCertificatePage(BaseModel):
    items: list[UniqueCertificate]
    total: int
    limit: int
    offset: int
    frontier: int


# ------------------------------------------------------------------ issues and certificate detail
class Issue(BaseModel):
    source: str
    kind: str
    code: str
    path: str | None
    seq: int | None


class IssuePage(BaseModel):
    items: list[Issue]
    total: int
    limit: int
    offset: int


class CertificateRun(BaseModel):
    run_id: str
    run_number: int
    sightings: int
    paths_count: int
    paths: list[str]
    paths_truncated: bool


class CertificateDetail(BaseModel):
    sha256: str
    serial_hex: str
    subject: str
    issuer: str
    san: list[SanEntry]
    key_algorithm: str
    key_size: int | None
    key_curve: str | None
    signature_algorithm: str
    not_before: str
    not_after: str
    is_ca: bool | None
    sightings_total: int
    runs_total: int
    runs_truncated: bool
    runs: list[CertificateRun]
