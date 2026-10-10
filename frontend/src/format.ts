// Display helpers. They never throw and never interpret text as markup.
import type { Run } from "./api/types";

const DASH = "—";

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const t = Date.parse(iso);
  // "10 Oct 2026, 14:13": the month is spelled out, so day and month can never be confused whatever the locale.
  return Number.isNaN(t) ? iso : new Date(t).toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms < 0) return DASH;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds - minutes * 60);
  if (minutes < 60) return `${minutes} min ${rest} s`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

/** Single reason codes: a run's `stop_reason`, or one whole `error_summary` token. */
const REASONS: Record<string, string> = {
  agent_not_connected: "No agent picked up the run in time.",
  agent_lost: "The agent stopped responding.",
  cancelled: "Cancelled.",
  stopped_cancelled: "The scan was cancelled before it finished.",
  invalid_config: "The agent rejected the scan settings.",
  agent_stopped: "The agent was stopped.",
  agent_error: "The agent hit an internal error.",
  agent_failed: "The agent reported a failure.",
  time_limit: "The scan hit its time budget.",
  stopped_time_limit: "The scan hit its time budget and stopped early.",
  stopped_enumeration_failed: "The agent could not read this machine's list of listening sockets, so nothing was probed.",
  stopped_target_limit: "The target limit was reached, so not every listener was probed.",
  no_usable_data: "No usable results were produced.",
  count_mismatch: "The agent's record count did not match what the backend stored.",
  stop_reason_missing: "The agent did not say why it stopped.",
  stopped_unknown: "The scan stopped early for a reason the backend could not read.",
};

/** `name:N` tokens of `error_summary` (backend/run_state.decide_outcome). */
const COUNTED: Record<string, (n: number) => string> = {
  roots_not_scanned: (n) => `${n} ${n === 1 ? "folder" : "folders"} could not be scanned.`,
  file_errors: (n) => `${n} ${n === 1 ? "read error was" : "read errors were"} recorded.`,
  records_rejected: (n) => `${n} ${n === 1 ? "record was" : "records were"} rejected by the backend.`,
  seq_conflicts: (n) => `${n} ${n === 1 ? "upload conflicted" : "uploads conflicted"} with data already stored.`,
  bundles_truncated: (n) => `${n} certificate ${n === 1 ? "bundle was" : "bundles were"} cut short.`,
};

/**
 * Counted tokens whose meaning differs for a TLS run. The backend shares the token `file_errors:N` between run types; for a
 * TLS run it counts scan errors (a failed listener enumeration, a probe that could not be made), never files that were read.
 */
const COUNTED_TLS: Record<string, (n: number) => string> = {
  file_errors: (n) => `${n} scan ${n === 1 ? "error was" : "errors were"} recorded.`,
};

/**
 * One `error_summary` token in words. `runType` selects wording for tokens the run types share; without it (or for any other
 * type) the filesystem wording is used. A token this UI does not know is returned unchanged (and rendered as text).
 */
export function explainToken(token: string, runType?: string): string {
  const counted = /^([a-z0-9_]+):(\d{1,9})$/.exec(token);
  if (counted) {
    const own = (table: Record<string, (n: number) => string>) => (Object.prototype.hasOwnProperty.call(table, counted[1]) ? table[counted[1]] : undefined);
    const words = (runType === "tls" ? own(COUNTED_TLS) : undefined) ?? own(COUNTED);
    if (words) return words(Number(counted[2]));
  }
  if (REASONS[token]) return REASONS[token];
  const stopped = /^stopped_([a-z0-9_]+)$/.exec(token);
  return stopped ? `The scan stopped early (${stopped[1]}).` : token;
}

/**
 * Why a partial or failed run ended, one sentence per reason. The backend records the real reasons in `error_summary`
 * (a comma-separated list) and gives such runs `stop_reason: "completed"` whenever the agent's scan itself ran to the end,
 * so `error_summary` comes first; `stop_reason` is only used when there is no summary and it is not the clean "completed".
 * Empty for runs that are neither partial nor failed.
 */
export function explainRun(run: Pick<Run, "status" | "stop_reason" | "error_summary"> & { type?: string }): string[] {
  if (run.status !== "partial" && run.status !== "failed") return [];
  const tokens = (run.error_summary ?? "").split(",").map((t) => t.trim()).filter(Boolean);
  if (tokens.length === 0 && run.stop_reason && run.stop_reason !== "completed") tokens.push(run.stop_reason);
  if (tokens.length === 0) return [run.status === "failed" ? "The run failed." : "The run ended early."];
  return tokens.map((token) => explainToken(token, run.type));
}

export function explainStop(run: Pick<Run, "status" | "stop_reason" | "error_summary"> & { type?: string }): string | null {
  const parts = explainRun(run);
  return parts.length ? parts.join(" ") : null;
}

/** Did this run end because someone cancelled it? */
export function wasCancelled(run: Pick<Run, "stop_reason" | "error_summary" | "cancel_requested">): boolean {
  const tokens = (run.error_summary ?? "").split(",").map((t) => t.trim());
  return tokens.includes("stopped_cancelled") || tokens.includes("cancelled") || (run.cancel_requested && run.stop_reason === "cancelled");
}

/**
 * The outcome column of the runs table. A completed run that reported no records is said to have reported none: what the
 * data establishes is "zero records", not that no certificate files existed (files the agent could not match or read are
 * not records), so the wording stops there.
 */
export function describeOutcome(run: Pick<Run, "status" | "stop_reason" | "error_summary" | "record_count"> & { type?: string }): string | null {
  if (run.status === "completed") return run.record_count === 0 ? "Completed, but the agent reported no records." : "Finished normally.";
  return explainStop(run);
}

/** Where a run scans: the folders it was given, or the agent's built-in default locations. */
export function describeScope(config: Record<string, unknown>): string {
  const roots = config.roots;
  if (!Array.isArray(roots)) return "Agent default locations";
  const names = roots.filter((r): r is string => typeof r === "string");
  if (names.length === 0) return DASH;
  return names.length === 1 ? names[0] : `${names[0]} (+${names.length - 1} more)`;
}

export const WAITING_FOR_AGENT_AFTER_MS = 20_000;

export function isWaitingForAgent(run: Pick<Run, "status" | "queued_at">, nowMs: number): boolean {
  if (run.status !== "queued") return false;
  const queued = Date.parse(run.queued_at);
  return !Number.isNaN(queued) && nowMs - queued > WAITING_FOR_AGENT_AFTER_MS;
}

export { DASH };

// ------------------------------------------------------------------ certificate report
const PARSE_LABELS: Record<string, string> = {
  ok: "Certificate read",
  malformed: "Could not be parsed",
  unsupported: "Unsupported content",
  too_large: "Too large to read",
  no_certificate: "No certificate in file",
  access_denied: "Access denied",
  read_error: "Read error",
  skipped: "Skipped",
};

export function parseStatusLabel(status: string): string {
  return PARSE_LABELS[status] ?? status;
}

const FORMAT_LABELS: Record<string, string> = { pem: "PEM", der: "DER", pkcs12: "PKCS#12", unknown: "Unknown" };

export function formatLabel(format: string): string {
  return FORMAT_LABELS[format] ?? format;
}

const WARNING_LABELS: Record<string, string> = {
  pkcs12_integrity_not_verified: "PKCS#12 integrity (MAC) was not verified",
  // TLS probe results
  active_probe: "Active probe attempt, not observed traffic",
  packet_counts_unavailable: "Packet counts are unavailable (no packet capture)",
  chain_unavailable: "Only the leaf certificate was available (the full chain could not be read)",
  chain_truncated: "The certificate chain was cut at 10 certificates",
  chain_unparsable: "A certificate further up the chain could not be parsed",
  certificate_unavailable: "The server completed the handshake but no certificate could be read",
  certificate_unparsable: "The server's certificate could not be parsed",
  connection_refused: "The connection was refused",
  connect_timeout: "The connection attempt timed out",
  connection_failed: "The connection could not be made",
  connection_reset: "The connection was reset during the handshake",
  handshake_timeout: "The handshake timed out",
  handshake_failed: "The TLS handshake failed (the service may not speak TLS)",
  unrecognised_handshake_details: "The handshake finished but its version or cipher was not recognised",
};

export function warningLabel(code: string): string {
  if (WARNING_LABELS[code]) return WARNING_LABELS[code];
  return code.includes("alert") ? `The service answered with a TLS alert (${code})` : code;
}

// ------------------------------------------------------------------ TLS probe results
export const PROBE_MARKERS = ["active_probe", "packet_counts_unavailable"];

const OUTCOME_LABELS: Record<string, string> = {
  completed: "TLS handshake completed",
  failed: "Handshake failed",
  alert: "TLS alert received",
  incomplete: "Probe incomplete",
  unknown: "Result unknown",
};

export function outcomeLabel(outcome: string): string {
  return OUTCOME_LABELS[outcome] ?? outcome;
}

/** Only a completed handshake is a TLS finding; a failed or inconclusive probe never is. */
export function isTlsFinding(outcome: string): boolean {
  return outcome === "completed";
}

const ATTRIBUTION_LABELS: Record<string, string> = {
  attributed: "Process identified",
  not_found: "Process not found",
  unavailable: "Process unavailable",
};

export function attributionLabel(status: string): string {
  return ATTRIBUTION_LABELS[status] ?? status;
}

/** The warnings that say something about THIS probe (the two constant method markers are explained once, in the notice). */
export function probeWarnings(warnings: string[]): string[] {
  return warnings.filter((w) => !PROBE_MARKERS.includes(w));
}

/** Where a run looks: for a TLS run the listeners on this machine (optionally narrowed by a port list), otherwise its folders. */
export function describeRunScope(run: Pick<Run, "type" | "config">): string {
  if (run.type !== "tls") return describeScope(run.config);
  const ports = run.config.ports;
  const list = Array.isArray(ports) ? ports.filter((p): p is number => typeof p === "number") : [];
  return list.length > 0 ? `TLS listeners on this machine (ports ${list.join(", ")})` : "TLS listeners on this machine";
}

/** A calendar date from an ISO timestamp, in the unambiguous form 2034-01-01 (UTC date as stored). */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const match = /^(\d{4}-\d{2}-\d{2})T/.exec(iso);
  return match ? match[1] : iso;
}

/** "RSA 2048", "EC P-256", or just the algorithm when no size or curve is recorded; a dash when nothing is. */
export function formatKey(algorithm: string | null | undefined, size: number | null | undefined, curve: string | null | undefined): string {
  if (!algorithm) return DASH;
  if (curve) return `${algorithm} ${curve}`;
  return size ? `${algorithm} ${size}` : algorithm;
}

/** Days to expiry as of the discovery time, in words. */
export function formatDays(days: number | null | undefined): string {
  if (days === null || days === undefined) return DASH;
  if (days < 0) return `expired ${-days} ${days === -1 ? "day" : "days"} before discovery`;
  return `${days} ${days === 1 ? "day" : "days"} left at discovery`;
}

export function shortHash(sha256: string): string {
  return sha256.length > 16 ? `${sha256.slice(0, 16)}…` : sha256;
}
