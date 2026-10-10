// Shapes of GET /api/runs/{run_id}/relationships (backend/relationship_models.py).
//
// What a row means:
//  * "stored_on"               a certificate was parsed from a file on that host (the file exists there; it says nothing about use).
//  * "presented_certificate"   a COMPLETED active TLS handshake against a LOCAL listener returned that certificate. Nothing was
//                              captured from traffic and no remote peer is involved.
//  * `filesystem_evidence`     SEPARATE evidence that a filesystem scan stored the same certificate (same SHA-256), maybe in other
//                              runs. It does not show that the listener uses that file.
export type RecordingState = "pending" | "recorded" | "none_expected" | "incomplete";

export interface RelationshipNode {
  kind: "certificate" | "host" | "endpoint";
  label: string;
  sha256?: string | null;
  host_id?: string | null;
  scope?: string | null;
  host?: { host_id: string; hostname: string | null } | null;
}

export interface SeenOnHost {
  host_id: string;
  hostname: string;
  observations: number;
  runs: number;
  last_seen_at: string;
  latest_run_id: string | null;
  latest_run_number: number | null;
}

export interface Relationship {
  kind: "stored_on" | "presented_certificate";
  label: string;
  source: RelationshipNode;
  target: RelationshipNode;
  in_run: { observations: number; first_at: string; last_at: string };
  all_runs: { observations: number; runs: number; first_seen_at: string; last_seen_at: string };
  process: { name: string; exe_path: string | null } | null;
  filesystem_evidence: { hosts: SeenOnHost[]; omitted: number } | null;
}

export interface RelationshipPage {
  run: { run_id: string; run_number: number; type: string; status: string; final: boolean };
  recording: { state: RecordingState; expected: number; recorded: number; missing: number; unexpected: number };
  counts: { stored_on: number; presented_certificate: number };
  items: Relationship[];
  total: number;
  limit: number;
  truncated: boolean;
}
