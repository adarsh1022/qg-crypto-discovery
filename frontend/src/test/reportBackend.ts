// A small in-memory report API for tests. The shapes mirror backend/report_models.py (what the real endpoints return).
import type { RelationshipPage } from "../api/relationshipTypes";
import type { CertificateDetail, Issue, Sighting, Summary, UniqueCertificate } from "../api/reportTypes";
import type { TlsObservation, TlsSummary } from "../api/tlsTypes";
import type { Run } from "../api/types";
import { backend } from "./fakeBackend";
import { makeTlsSummary } from "./tlsFixtures";
import { errorResponse, jsonResponse, makeRun, type Req } from "./helpers";

export const sha = (n: number) => n.toString(16).padStart(64, "0");

const ZERO = { valid: 0, expiring: 0, expired: 0, not_yet_valid: 0 };

export function makeSummary(run: Run, over: Partial<Summary["totals"]> = {}, extra: Partial<Summary> = {}): Summary {
  return {
    run: { run_id: run.run_id, run_number: run.run_number, type: run.type, status: run.status, final: ["completed", "partial", "failed"].includes(run.status), started_at: run.started_at, finished_at: run.finished_at },
    as_of: "2026-10-10T08:00:00.000Z",
    frontier: 10,
    expiring_days: { value: 30, source: "default" },
    totals: {
      records: 0, sightings: 0, unique_certificates: 0, duplicate_observations: { total: 0, within_file: 0, across_files: 0 },
      parse_failures: 0, no_certificate: 0, skipped: 0, ...over,
    },
    parse_status: { ok: 0, malformed: 0, unsupported: 0, too_large: 0, no_certificate: 0, access_denied: 0, read_error: 0, skipped: 0 },
    validity: { at_discovery: { ...ZERO }, now: { unique: { ...ZERO }, sightings: { ...ZERO } } },
    issues: { errors: { total: 0, file_errors: 0, directory_errors: 0, unresolved_read_errors: 0 }, rejected: 0, seq_conflicts: 0 },
    ...extra,
  };
}

export function makeCert(n: number, over: Partial<UniqueCertificate> = {}): UniqueCertificate {
  return {
    sha256: sha(n), subject: `CN=host${n}.example`, issuer: "CN=Example CA", not_before: "2024-01-01T00:00:00Z", not_after: "2034-01-01T00:00:00Z",
    key_algorithm: "RSA", key_size: 2048, key_curve: null, signature_algorithm: "sha256WithRSAEncryption", sightings: 1, paths: 1, ...over,
  };
}

export function makeSighting(seq: number, over: Partial<Sighting> = {}): Sighting {
  return {
    seq, entry_ordinal: 0, path: `C:\\certs\\file${seq}.pem`, filename: `file${seq}.pem`, scan_root: "C:\\certs", format: "pem", discovered_at: "2026-10-10T08:00:00Z",
    sha256: sha(seq + 1), chain_index: 0, chain_total: 1, chain_role: "leaf", parse_status: "ok", detail: null, access_error: null, evidence_confidence: "high",
    validity_status: "valid", days_to_expiry: 2600, duplicate_kind: "none", serial_hex: "0a1b2c", subject: `CN=host${seq + 1}.example`, issuer: "CN=Example CA",
    san: [{ type: "dns", value: `host${seq + 1}.example` }], key_algorithm: "RSA", key_size: 2048, key_curve: null, signature_algorithm: "sha256WithRSAEncryption",
    not_before: "2024-01-01T00:00:00Z", not_after: "2034-01-01T00:00:00Z", warnings: [], ...over,
  };
}

export function makeKeyOnly(seq: number, over: Partial<Sighting> = {}): Sighting {
  return makeSighting(seq, {
    format: "pem", sha256: null, chain_index: null, chain_total: null, chain_role: null, parse_status: "no_certificate", detail: "no_certificate_block",
    evidence_confidence: "low", validity_status: null, days_to_expiry: null, serial_hex: null, subject: null, issuer: null, san: null, key_algorithm: null,
    key_size: null, signature_algorithm: null, not_before: null, not_after: null, ...over,
  });
}

export function makeIssue(over: Partial<Issue> = {}): Issue {
  return { source: "agent", kind: "root", code: "FileNotFoundError:WinError 2", path: "C:\\gone", seq: null, ...over };
}

export function makeDetail(n: number, over: Partial<CertificateDetail> = {}): CertificateDetail {
  return {
    sha256: sha(n), serial_hex: "0a1b2c3d", subject: `CN=host${n}.example`, issuer: "CN=Example CA", san: [{ type: "dns", value: `host${n}.example` }, { type: "ip", value: "10.0.0.5" }],
    key_algorithm: "RSA", key_size: 2048, key_curve: null, signature_algorithm: "sha256WithRSAEncryption", not_before: "2024-01-01T00:00:00Z", not_after: "2034-01-01T00:00:00Z",
    is_ca: false, sightings_total: 1, runs_total: 1, ...over,
  };
}

export function makeRelationships(run: Run, over: Partial<RelationshipPage> = {}): RelationshipPage {
  const final = ["completed", "partial", "failed"].includes(run.status);
  return {
    run: { run_id: run.run_id, run_number: run.run_number, type: run.type, status: run.status, final },
    recording: { state: final ? "none_expected" : "pending", expected: 0, recorded: 0, missing: 0, unexpected: 0 },
    counts: { stored_on: 0, presented_certificate: 0 },
    items: [], total: 0, limit: 200, truncated: false, ...over,
  };
}

export interface RunData {
  relationships?: RelationshipPage;
  tlsSummary?: TlsSummary;
  tlsObservations?: TlsObservation[];
  tlsIssues?: Issue[];
  summary?: Summary;
  certs?: UniqueCertificate[];
  sightings?: Sighting[];
  issues?: Issue[];
}

/** Serves /api/runs... from `runs` and the report endpoints from `data` (keyed by run id). Unknown runs get 404 run_not_found. */
export function reportBackend(runs: Run[], data: Record<string, RunData>, details: Record<string, CertificateDetail> = {}) {
  const base = backend(runs);
  const handler = (req: Req): Response | Promise<Response> => {
    const m = /^\/api\/runs\/([0-9a-f]{32})\/(fs\/summary|fs\/certificates|fs\/observations|issues)$/.exec(req.path);
    if (m && req.method === "GET") {
      const run = base.runs.find((r) => r.run_id === m[1]);
      if (!run) return errorResponse(404, "run_not_found", "No such run.");
      if (run.type !== "filesystem") return errorResponse(409, "wrong_run_type", "x", { required_type: "filesystem" });
      const d = data[m[1]] ?? {};
      const limit = Number(req.query.get("limit") ?? 100);
      const offset = Number(req.query.get("offset") ?? 0);
      const frontier = Number(req.query.get("frontier") ?? 10);
      const slice = <T,>(all: T[]) => ({ items: all.slice(offset, offset + limit), total: all.length, limit, offset });
      switch (m[2]) {
        case "fs/summary":
          return jsonResponse(d.summary ?? makeSummary(run));
        case "fs/certificates":
          return jsonResponse({ ...slice(d.certs ?? []), frontier });
        case "fs/observations": {
          let rows = d.sightings ?? [];
          const q = req.query.get("q");
          const parse = req.query.get("parse_status");
          const validity = req.query.get("validity_status");
          const fp = req.query.get("fingerprint");
          if (q) rows = rows.filter((r) => `${r.path} ${r.subject ?? ""} ${r.issuer ?? ""}`.toLowerCase().includes(q.toLowerCase()));
          if (parse) rows = rows.filter((r) => r.parse_status === parse);
          if (validity) rows = rows.filter((r) => r.validity_status === validity);
          if (fp) rows = rows.filter((r) => r.sha256?.startsWith(fp));
          return jsonResponse({ ...slice(rows), frontier });
        }
        default:
          return jsonResponse(slice(d.issues ?? []));
      }
    }
    const t = /^\/api\/runs\/([0-9a-f]{32})\/tls\/(summary|observations|issues)$/.exec(req.path);
    if (t && req.method === "GET") {
      const run = base.runs.find((r) => r.run_id === t[1]);
      if (!run) return errorResponse(404, "run_not_found", "No such run.");
      if (run.type !== "tls") return errorResponse(409, "wrong_run_type", "x", { required_type: "tls" });
      const d = data[t[1]] ?? {};
      const limit = Number(req.query.get("limit") ?? 100);
      const offset = Number(req.query.get("offset") ?? 0);
      const frontier = Number(req.query.get("frontier") ?? 10);
      if (t[2] === "summary") return jsonResponse(d.tlsSummary ?? makeTlsSummary(run));
      if (t[2] === "issues") {
        const all = d.tlsIssues ?? [];
        return jsonResponse({ items: all.slice(offset, offset + limit), total: all.length, limit, offset });
      }
      let rows = d.tlsObservations ?? [];
      const outcome = req.query.get("outcome");
      const version = req.query.get("tls_version");
      const attribution = req.query.get("process_attribution");
      const fp = req.query.get("fingerprint");
      const q = req.query.get("q");
      if (outcome) rows = rows.filter((r) => r.handshake_outcome === outcome);
      if (version) rows = rows.filter((r) => r.tls_version === version);
      if (attribution) rows = rows.filter((r) => r.process_attribution === attribution);
      if (fp) rows = rows.filter((r) => r.peer_certificates.some((c) => c.sha256.startsWith(fp)));
      if (q) rows = rows.filter((r) => `${r.dst_ip} ${r.process_name ?? ""} ${r.peer_certificates[0]?.subject ?? ""}`.toLowerCase().includes(q.toLowerCase()));
      return jsonResponse({ items: rows.slice(offset, offset + limit), total: rows.length, limit, offset, frontier });
    }
    const r = /^\/api\/runs\/([0-9a-f]{32})\/relationships$/.exec(req.path);
    if (r && req.method === "GET") {
      const run = base.runs.find((x) => x.run_id === r[1]);
      if (!run) return errorResponse(404, "run_not_found", "No such run.");
      return jsonResponse((data[r[1]] ?? {}).relationships ?? makeRelationships(run));
    }
    const c = /^\/api\/certificates\/([0-9a-f]{64})$/.exec(req.path);
    if (c && req.method === "GET") {
      return details[c[1]] ? jsonResponse(details[c[1]]) : errorResponse(404, "certificate_not_found", "No such certificate.");
    }
    return base.handler(req);
  };
  return { runs: base.runs, handler };
}

export { makeRun };
