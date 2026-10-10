// Shapes of the backend's TLS report API (backend/tls_report_models.py).
//
// Every row is ONE ACTIVE PROBE ATTEMPT by the agent against a listener on this machine. It is not observed traffic:
// `direction` is always "unknown", `event_count` is 1 (one probe attempt) and `packet_count` is 0 (packet counts are
// unavailable because nothing is captured). Only handshake_outcome === "completed" is a TLS finding.
import type { ValidityCounts } from "./reportTypes";

export const TLS_OUTCOMES = ["completed", "failed", "alert", "incomplete", "unknown"] as const;
export const TLS_VERSIONS = ["SSL3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"] as const;
export const ATTRIBUTIONS = ["attributed", "not_found", "unavailable"] as const;

export interface TlsSummary {
  run: { run_id: string; run_number: number; type: string; status: string; final: boolean; started_at: string | null; finished_at: string | null };
  as_of: string;
  frontier: number;
  totals: {
    probe_attempts: number;
    handshakes_completed: number; // the only TLS findings
    not_completed: number; // failed, incomplete, alert or unknown probes: NOT findings
    endpoints: number;
    certificates_presented: number;
    leaf_certificates: number;
  };
  outcomes: Record<string, number>;
  tls_versions: Record<string, number>; // completed handshakes only
  cipher_suites: { top: Array<{ cipher_suite: string | null; handshakes: number }>; other: { groups: number; handshakes: number } | null; total_groups: number; limit: number };
  process_attribution: Record<string, number>;
  certificate_validity: { expiring_days: { value: number; source: string }; now: ValidityCounts };
  issues: { errors: { total: number; enumerate: number; probe: number }; rejected: number; seq_conflicts: number };
  scan: {
    stop_reason: string | null;
    enumeration: string | null; // "ok" or "failed"
    listeners_found: number | null;
    port_filtered: number | null;
    policy_skipped: number | null;
    targets_planned: number | null;
    targets_probed: number | null;
    targets_truncated: boolean | null;
  } | null; // null until the run has finished
}

export interface PeerCertificate {
  position: number; // 0 = leaf
  sha256: string;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  key_algorithm: string;
  key_size: number | null;
  key_curve: string | null;
  signature_algorithm: string;
  is_ca: boolean | null;
}

export interface TlsObservation {
  seq: number;
  observed_at: string;
  direction: string;
  transport: string;
  src_ip: string; // the probe's own socket
  src_port: number;
  dst_ip: string; // the listener that was probed
  dst_port: number;
  handshake_outcome: string;
  sni: string | null;
  tls_version: string | null;
  cipher_suite: string | null;
  cert_visibility: string;
  pid: number | null;
  process_name: string | null;
  exe_path: string | null;
  process_attribution: string;
  event_count: number;
  packet_count: number;
  event_counts: Record<string, number>;
  evidence_confidence: string;
  warnings: string[];
  peer_certificates: PeerCertificate[];
}

export interface TlsObservationQuery {
  outcome?: string;
  tls_version?: string;
  process_attribution?: string;
  dst_port?: number;
  fingerprint?: string;
  q?: string;
  sort?: string;
  direction?: "asc" | "desc";
  limit?: number;
  offset?: number;
  frontier?: number;
}
