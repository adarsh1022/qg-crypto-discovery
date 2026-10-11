// Shapes of the backend's dashboard endpoints (backend/report_models.py: Dashboard, RunStatistics, RunBrief, Ranked, ...).
//
// GET /api/runs/stats  -> counts of ALL runs by (type, status), plus a bounded series of the most recent runs.
// GET /api/dashboard   -> the newest FINISHED filesystem run and its summary. Everything certificate-related describes that one
//                         run, not all runs: `latest_terminal_fs_run` says which.
import type { Summary } from "./reportTypes";

export interface RunBrief {
  run_id: string;
  run_number: number;
  type: string;
  status: string;
  started_at: string | null;
  duration_ms: number | null;
  record_count: number;
  finding_count: number;
}

export interface TypeStatusCount {
  type: string;
  status: string;
  count: number;
}

export interface RunStatistics {
  by_type_status: TypeStatusCount[];
  series: RunBrief[];
}

export interface RankedGroup<Item, Other> {
  top: Item[];
  other: Other | null;
  total_groups: number;
  limit: number;
}

export interface AlgorithmItem {
  key_algorithm: string | null;
  key_size: number | null;
  key_curve: string | null;
  unique: number;
  sightings: number;
}

export interface SignatureItem {
  signature_algorithm: string | null;
  unique: number;
  sightings: number;
}

export interface OtherCertificates {
  groups: number;
  unique: number;
  sightings: number;
}

/** The per-run filesystem summary as the dashboard embeds it (the report page types only the part it shows). */
export interface DashboardSummary extends Summary {
  algorithms: RankedGroup<AlgorithmItem, OtherCertificates>;
  signature_algorithms: RankedGroup<SignatureItem, OtherCertificates>;
}

export interface Dashboard {
  latest_run: RunBrief | null;
  latest_terminal_fs_run: RunBrief | null;
  summary: DashboardSummary | null;
  runs_by_status: Record<string, number>;
  recent_runs: RunBrief[];
}
