// Builders shaped exactly like backend/tls_report_models.py (what the real TLS report endpoints return).
import type { PeerCertificate, TlsObservation, TlsSummary } from "../api/tlsTypes";
import type { Run } from "../api/types";

const MARKERS = ["active_probe", "packet_counts_unavailable"];
export const sha = (n: number) => n.toString(16).padStart(64, "0");

export function makePeer(n: number, position = 0, over: Partial<PeerCertificate> = {}): PeerCertificate {
  return {
    position, sha256: sha(n), subject: `CN=tls${n}.example`, issuer: "CN=Example CA", not_before: "2024-01-01T00:00:00Z", not_after: "2034-01-01T00:00:00Z",
    key_algorithm: "RSA", key_size: 2048, key_curve: null, signature_algorithm: "sha256WithRSAEncryption", is_ca: position === 0 ? false : true, ...over,
  };
}

/** A COMPLETED handshake against 127.0.0.1:`port`. */
export function makeProbe(seq: number, over: Partial<TlsObservation> = {}): TlsObservation {
  return {
    seq, observed_at: "2026-10-10T08:00:00Z", direction: "unknown", transport: "tcp", src_ip: "127.0.0.1", src_port: 50000 + seq, dst_ip: "127.0.0.1",
    dst_port: 8000 + seq, handshake_outcome: "completed", sni: null, tls_version: "TLS1.3", cipher_suite: "TLS_AES_256_GCM_SHA384",
    cert_visibility: "visible", pid: 4321, process_name: "svc.exe", exe_path: "C:\\Program Files\\svc\\svc.exe", process_attribution: "attributed",
    event_count: 1, packet_count: 0, event_counts: { probe_attempts: 1, handshake_completed: 1 }, evidence_confidence: "high",
    warnings: [...MARKERS], peer_certificates: [makePeer(seq + 1)], ...over,
  };
}

/** A probe that is NOT a TLS finding: no version, cipher or certificate. */
export function makeInconclusive(seq: number, outcome = "failed", code = "handshake_failed", over: Partial<TlsObservation> = {}): TlsObservation {
  return makeProbe(seq, {
    handshake_outcome: outcome, tls_version: null, cipher_suite: null, cert_visibility: "not_observed", peer_certificates: [], evidence_confidence: "low",
    warnings: [...MARKERS, code], pid: null, process_name: null, exe_path: null, process_attribution: "unavailable",
    event_counts: { probe_attempts: 1, handshake_completed: 0 }, ...over,
  });
}

export function makeTlsSummary(run: Run, over: Partial<TlsSummary> = {}, totals: Partial<TlsSummary["totals"]> = {}): TlsSummary {
  return {
    run: { run_id: run.run_id, run_number: run.run_number, type: run.type, status: run.status, final: ["completed", "partial", "failed"].includes(run.status), started_at: run.started_at, finished_at: run.finished_at },
    as_of: "2026-10-10T08:00:00.000Z", frontier: 10,
    totals: { probe_attempts: 0, handshakes_completed: 0, not_completed: 0, endpoints: 0, certificates_presented: 0, leaf_certificates: 0, ...totals },
    outcomes: { completed: 0, failed: 0, alert: 0, incomplete: 0, unknown: 0 },
    tls_versions: { SSL3: 0, "TLS1.0": 0, "TLS1.1": 0, "TLS1.2": 0, "TLS1.3": 0 },
    cipher_suites: { top: [], other: null, total_groups: 0, limit: 20 },
    process_attribution: { attributed: 0, not_found: 0, unavailable: 0 },
    certificate_validity: { expiring_days: { value: 30, source: "default" }, now: { valid: 0, expiring: 0, expired: 0, not_yet_valid: 0 } },
    issues: { errors: { total: 0, enumerate: 0, probe: 0 }, rejected: 0, seq_conflicts: 0 },
    scan: null, ...over,
  };
}

export const SCAN_OK = { stop_reason: "completed", enumeration: "ok", listeners_found: 12, port_filtered: 0, policy_skipped: 2, targets_planned: 10, targets_probed: 10, targets_truncated: false };
