// Builders for relationship API payloads (shapes: backend/relationship_models.py).
import type { Relationship, RelationshipPage } from "../api/relationshipTypes";
import type { Run } from "../api/types";
import { sha } from "./reportBackend";

const TIMES = { first_at: "2026-10-10T08:00:00Z", last_at: "2026-10-10T08:05:00Z" };
const ALL = { first_seen_at: "2026-10-09T08:00:00Z", last_seen_at: "2026-10-10T08:05:00Z" };

export function makeStoredOn(n: number, over: Partial<Relationship> = {}): Relationship {
  return {
    kind: "stored_on", label: "Certificate parsed from a file on this host",
    source: { kind: "certificate", label: `CN=host${n}.example`, sha256: sha(n) },
    target: { kind: "host", label: "WORKSTATION", host_id: "agent-1" },
    in_run: { observations: 2, ...TIMES }, all_runs: { observations: 5, runs: 3, ...ALL },
    process: null, filesystem_evidence: null, ...over,
  };
}

export function makePresented(n: number, over: Partial<Relationship> = {}): Relationship {
  return {
    kind: "presented_certificate", label: "Certificate presented by a local listener (active probe)",
    source: { kind: "endpoint", label: `127.0.0.1:${8000 + n}/tcp`, scope: "local_listener", host: { host_id: "agent-1", hostname: "WORKSTATION" } },
    target: { kind: "certificate", label: `CN=host${n}.example`, sha256: sha(n) },
    in_run: { observations: 1, ...TIMES }, all_runs: { observations: 1, runs: 1, ...ALL },
    process: { name: "svc.exe", exe_path: "C:\\svc\\svc.exe" }, filesystem_evidence: { hosts: [], omitted: 0 }, ...over,
  };
}

export function recorded(run: Run, items: Relationship[], over: Partial<RelationshipPage> = {}): RelationshipPage {
  const stored = items.filter((i) => i.kind === "stored_on").length;
  return {
    run: { run_id: run.run_id, run_number: run.run_number, type: run.type, status: run.status, final: true },
    recording: { state: "recorded", expected: items.length, recorded: items.length, missing: 0, unexpected: 0 },
    counts: { stored_on: stored, presented_certificate: items.length - stored },
    items, total: items.length, limit: 200, truncated: false, ...over,
  };
}
