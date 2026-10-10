// Shapes of the backend's run API (backend/api_models.py: RunView, RunEnvelope, RunListEnvelope, CreateRunRequest).

export const RUN_STATUSES = ["queued", "running", "completed", "partial", "failed"] as const;
export type RunStatus = (typeof RUN_STATUSES)[number];
export const RUN_TYPES = ["filesystem", "tls"] as const;
export type RunType = (typeof RUN_TYPES)[number];

export interface Run {
  run_id: string;
  run_number: number;
  type: string;
  trigger: string;
  schedule_id: string | null;
  status: string; // one of RUN_STATUSES; anything else is shown as "unknown", never trusted
  config: Record<string, unknown>;
  host_id: string | null;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  last_heartbeat_at: string | null;
  duration_ms: number | null;
  stop_reason: string | null;
  cancel_requested: boolean;
  cancel_requested_at: string | null;
  record_count: number;
  finding_count: number; // certificate sightings: records that carry a certificate
  rejected_count: number;
  error_count: number;
  error_summary: string | null;
  agent_summary: Record<string, unknown> | null; // null in list responses
}

/** The filesystem scan settings the backend accepts (service.FS_CONFIG_KEYS); the form uses a subset. */
export interface FsConfig {
  roots?: string[];
  extensions?: string[];
  exclude_dir_names?: string[];
  exclude_paths?: string[];
  max_file_bytes?: number;
  max_entries?: number;
  max_candidates?: number;
  max_certs_per_file?: number;
  max_depth?: number;
  expiring_days?: number;
  time_budget_seconds?: number;
}

/**
 * The TLS scan settings the backend accepts (service.TLS_CONFIG_KEYS). `ports` can only NARROW the listeners the agent finds in
 * the operating system's table of listening sockets; there is deliberately no way to name a host or address.
 */
export interface TlsConfig {
  ports?: number[];
  max_targets?: number;
  connect_timeout_seconds?: number;
  handshake_timeout_seconds?: number;
  time_budget_seconds?: number;
}

export type CreateRunBody = { type: "filesystem"; config: FsConfig } | { type: "tls"; config: TlsConfig };

// ------------------------------------------------------------------ schedules (backend/schedule_models.py)
export const MIN_INTERVAL_SECONDS = 15;
export const MAX_INTERVAL_SECONDS = 7 * 24 * 3600;
export const SCHEDULE_STATES = ["waiting", "skipping", "paused"] as const;
export type ScheduleState = (typeof SCHEDULE_STATES)[number];

/** The run a schedule last created, as the backend stores it. `status` is the run's real lifecycle status. */
export interface ScheduleLastRun {
  run_id: string;
  run_number: number;
  status: string;
  queued_at: string;
  finished_at: string | null;
}

export interface Schedule {
  schedule_id: string;
  run_type: string;
  interval_seconds: number;
  config: Record<string, unknown>;
  probe_all_listeners: boolean; // a TLS schedule that probes every eligible listener on this machine
  enabled: boolean;
  state: string; // one of SCHEDULE_STATES; anything else is shown as "unknown", never trusted
  next_due_at: string | null; // null while paused
  created_at: string;
  last_run: ScheduleLastRun | null;
  run_count: number;
}

export interface CreateScheduleBody {
  run_type: "filesystem" | "tls";
  interval_seconds: number;
  config: FsConfig | TlsConfig;
  enabled?: boolean;
  probe_all_listeners?: boolean; // TLS only: the explicit opt-in the backend requires when no ports are listed
}

export interface RunFilters {
  type?: RunType;
  status?: RunStatus;
}

export function isActive(run: Pick<Run, "status">): boolean {
  return run.status === "queued" || run.status === "running";
}
