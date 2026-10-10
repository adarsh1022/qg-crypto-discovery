"""Response models for GET /api/runs/{run_id}/relationships (pydantic v2): an allow-list of what may leave the service.

A field becomes public only by being listed here. No internal row ids, no raw certificate bytes, no private-key material, no PID
(a process is never an identity here), no lease or token material.

Reading the rows correctly
  kind "stored_on"               a certificate was parsed from a file on that host. Existence of a file, not use.
  kind "presented_certificate"   a COMPLETED active TLS handshake against a LOCAL listener returned that certificate. The listener
                                 is an endpoint on the host named in `source.host`; nothing was captured from traffic.
  `filesystem_evidence`          separate evidence that a filesystem scan stored the same certificate (same SHA-256) in a file,
                                 possibly in other runs. It does not show that the listener uses that file.
"""
from __future__ import annotations

from pydantic import BaseModel


class RunRef(BaseModel):
    run_id: str
    run_number: int
    type: str
    status: str
    final: bool


class Recording(BaseModel):
    state: str                      # pending | recorded | none_expected | incomplete
    expected: int
    recorded: int
    missing: int
    unexpected: int


class HostRef(BaseModel):
    host_id: str
    hostname: str | None


class Node(BaseModel):
    kind: str
    label: str
    sha256: str | None = None
    host_id: str | None = None
    scope: str | None = None
    host: HostRef | None = None


class InRun(BaseModel):
    observations: int
    first_at: str
    last_at: str


class AllRuns(BaseModel):
    observations: int
    runs: int
    first_seen_at: str
    last_seen_at: str


class Process(BaseModel):
    name: str
    exe_path: str | None


class SeenOnHost(BaseModel):
    host_id: str
    hostname: str
    observations: int
    runs: int
    last_seen_at: str
    latest_run_id: str | None
    latest_run_number: int | None


class FilesystemEvidence(BaseModel):
    hosts: list[SeenOnHost]
    omitted: int


class Relationship(BaseModel):
    kind: str
    label: str
    source: Node
    target: Node
    in_run: InRun
    all_runs: AllRuns
    process: Process | None
    filesystem_evidence: FilesystemEvidence | None


class RelationshipCounts(BaseModel):
    stored_on: int
    presented_certificate: int


class RelationshipPage(BaseModel):
    run: RunRef
    recording: Recording
    counts: RelationshipCounts
    items: list[Relationship]
    total: int
    limit: int
    truncated: bool
