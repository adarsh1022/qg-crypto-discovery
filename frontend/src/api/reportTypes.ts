// Shapes of the backend's filesystem report API (backend/report_models.py). Only fields the backend publishes appear here;
// `owning_process` is deliberately absent (the backend always sends null for filesystem scans).

export interface ValidityCounts {
  valid: number;
  expiring: number;
  expired: number;
  not_yet_valid: number;
}

export interface Summary {
  run: { run_id: string; run_number: number; type: string; status: string; final: boolean; started_at: string | null; finished_at: string | null };
  as_of: string;
  frontier: number;
  expiring_days: { value: number; source: string };
  totals: {
    records: number;
    sightings: number;
    unique_certificates: number;
    duplicate_observations: { total: number; within_file: number; across_files: number };
    parse_failures: number;
    no_certificate: number;
    skipped: number;
  };
  parse_status: Record<string, number>;
  validity: { at_discovery: ValidityCounts; now: { unique: ValidityCounts; sightings: ValidityCounts } };
  issues: {
    errors: { total: number; file_errors: number; directory_errors: number; unresolved_read_errors: number };
    rejected: number;
    seq_conflicts: number;
  };
}

export interface SanEntry {
  type: string;
  value: string;
}

/** One file record (a "sighting" when it carries a certificate). */
export interface Sighting {
  seq: number;
  entry_ordinal: number;
  path: string;
  filename: string;
  scan_root: string;
  format: string;
  discovered_at: string;
  sha256: string | null;
  chain_index: number | null;
  chain_total: number | null;
  chain_role: string | null;
  parse_status: string;
  detail: string | null;
  access_error: string | null;
  evidence_confidence: string;
  validity_status: string | null; // as of discovery
  days_to_expiry: number | null; // as of discovery
  duplicate_kind: string;
  serial_hex: string | null;
  subject: string | null;
  issuer: string | null;
  san: SanEntry[] | null;
  key_algorithm: string | null;
  key_size: number | null;
  key_curve: string | null;
  signature_algorithm: string | null;
  not_before: string | null;
  not_after: string | null;
  warnings: string[];
}

export interface UniqueCertificate {
  sha256: string;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  key_algorithm: string;
  key_size: number | null;
  key_curve: string | null;
  signature_algorithm: string;
  sightings: number;
  paths: number;
}

export interface Issue {
  source: string;
  kind: string;
  code: string;
  path: string | null;
  seq: number | null;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  frontier: number; // absent on the issues page
}

export interface CertificateDetail {
  sha256: string;
  serial_hex: string;
  subject: string;
  issuer: string;
  san: SanEntry[];
  key_algorithm: string;
  key_size: number | null;
  key_curve: string | null;
  signature_algorithm: string;
  not_before: string;
  not_after: string;
  is_ca: boolean | null;
  sightings_total: number;
  runs_total: number;
}

export interface SightingQuery {
  q?: string;
  parse_status?: string;
  validity_status?: string;
  fingerprint?: string;
  sort?: string;
  direction?: "asc" | "desc";
  limit?: number;
  offset?: number;
  frontier?: number;
}

export interface CertificateQuery {
  sort?: string;
  direction?: "asc" | "desc";
  limit?: number;
  offset?: number;
  frontier?: number;
}

export const PARSE_STATUSES = ["ok", "malformed", "unsupported", "too_large", "no_certificate", "access_denied", "read_error", "skipped"] as const;
export const VALIDITY_STATUSES = ["valid", "expiring", "expired"] as const;
