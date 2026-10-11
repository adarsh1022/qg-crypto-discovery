// Pure mapping from the backend's dashboard responses to chart rows. No fetching and no invented values: every number comes
// straight from a response field, and nothing is shown that the response does not contain.
import type { Dashboard, DashboardSummary, RunStatistics } from "./api/dashboardTypes";
import { TLS_VERSIONS, type TlsSummary } from "./api/tlsTypes";
import { formatKey } from "./format";

export type Tone = "series1" | "series2" | "valid" | "expiring" | "expired" | "neutral";

export interface Segment {
  key: string;
  label: string;
  value: number;
  tone: Tone;
}

export interface ChartRow {
  key: string;
  label: string;
  value: number;
  tone: Tone;
  /** A symbol repeated in text (never the only carrier of meaning): status colours always come with an icon and a label. */
  icon?: string;
  /** Extra words after the value, e.g. "(3 sightings)". */
  detail?: string;
  /** For stacked bars: the parts that add up to `value`. */
  segments?: Segment[];
}

export const STATUS_ORDER = ["queued", "running", "completed", "partial", "failed"] as const;
const STATUS_LABEL: Record<string, string> = { queued: "Queued", running: "Running", completed: "Completed", partial: "Partial", failed: "Failed" };
const TYPE_LABEL: Record<string, string> = { filesystem: "Filesystem", tls: "TLS" };
const TYPE_TONE: Record<string, Tone> = { filesystem: "series1", tls: "series2" };
const TYPE_ORDER = ["filesystem", "tls"];

export const typeLabel = (type: string) => TYPE_LABEL[type] ?? type;

// ------------------------------------------------------------------ runs by status and type  (GET /api/runs/stats)
export function runsByStatusAndType(stats: RunStatistics) {
  const types = [...new Set(stats.by_type_status.map((g) => g.type))].sort((a, b) => {
    const [x, y] = [TYPE_ORDER.indexOf(a), TYPE_ORDER.indexOf(b)];
    return (x === -1 ? 99 : x) - (y === -1 ? 99 : y) || a.localeCompare(b);
  });
  const legend = types.map((type) => ({ key: type, label: typeLabel(type), tone: TYPE_TONE[type] ?? ("neutral" as Tone) }));
  const rows: ChartRow[] = STATUS_ORDER.map((status) => {
    const segments: Segment[] = types.map((type) => ({
      key: type,
      label: typeLabel(type),
      value: stats.by_type_status.filter((g) => g.type === type && g.status === status).reduce((n, g) => n + g.count, 0),
      tone: TYPE_TONE[type] ?? "neutral",
    }));
    return { key: status, label: STATUS_LABEL[status], value: segments.reduce((n, s) => n + s.value, 0), tone: "series1", segments };
  });
  const total = rows.reduce((n, r) => n + r.value, 0);
  return { rows, legend, total };
}

// ------------------------------------------------------------------ certificate validity  (GET /api/dashboard -> summary.validity.now.unique)
export function validityRows(summary: DashboardSummary): ChartRow[] {
  const counts = summary.validity.now.unique;
  const days = summary.expiring_days.value;
  return [
    { key: "valid", label: "Valid", value: counts.valid, tone: "valid", icon: "✓" },
    { key: "expiring", label: `Expiring within ${days} day${days === 1 ? "" : "s"}`, value: counts.expiring, tone: "expiring", icon: "!" },
    { key: "expired", label: "Expired", value: counts.expired, tone: "expired", icon: "✕" },
    { key: "not_yet_valid", label: "Not yet valid", value: counts.not_yet_valid, tone: "neutral", icon: "…" },
  ];
}

// ------------------------------------------------------------------ algorithms  (summary.algorithms / summary.signature_algorithms)
export function keyAlgorithmRows(summary: DashboardSummary): ChartRow[] {
  const ranked = summary.algorithms;
  const rows: ChartRow[] = ranked.top.map((item, index) => ({
    key: `${index}|${item.key_algorithm}|${item.key_size}|${item.key_curve}`,
    label: item.key_algorithm === null ? "Unknown" : formatKey(item.key_algorithm, item.key_size, item.key_curve),
    value: item.unique,
    tone: "series1",
    detail: item.sightings !== item.unique ? `(${item.sightings} sightings)` : undefined,
  }));
  if (ranked.other) rows.push({ key: "other", label: `Other (${ranked.other.groups} more)`, value: ranked.other.unique, tone: "neutral" });
  return rows;
}

export function signatureRows(summary: DashboardSummary): ChartRow[] {
  const ranked = summary.signature_algorithms;
  const rows: ChartRow[] = ranked.top.map((item, index) => ({
    key: `${index}|${item.signature_algorithm}`,
    label: item.signature_algorithm ?? "Unknown",
    value: item.unique,
    tone: "series1",
    detail: item.sightings !== item.unique ? `(${item.sightings} sightings)` : undefined,
  }));
  if (ranked.other) rows.push({ key: "other", label: `Other (${ranked.other.groups} more)`, value: ranked.other.unique, tone: "neutral" });
  return rows;
}

// ------------------------------------------------------------------ TLS  (GET /api/runs/{id}/tls/summary: completed handshakes only)
export function tlsVersionRows(summary: TlsSummary): ChartRow[] {
  const known: string[] = [...TLS_VERSIONS];
  const names = [...known.filter((v) => v in summary.tls_versions), ...Object.keys(summary.tls_versions).filter((v) => !known.includes(v)).sort()];
  return names.filter((name) => summary.tls_versions[name] > 0).map((name) => ({ key: name, label: name, value: summary.tls_versions[name], tone: "series1" as Tone }));
}

export function cipherRows(summary: TlsSummary): ChartRow[] {
  const ranked = summary.cipher_suites;
  const rows: ChartRow[] = ranked.top.map((item, index) => ({
    key: `${index}|${item.cipher_suite}`,
    label: item.cipher_suite ?? "Not reported",
    value: item.handshakes,
    tone: "series1",
  }));
  if (ranked.other) rows.push({ key: "other", label: `Other (${ranked.other.groups} more)`, value: ranked.other.handshakes, tone: "neutral" });
  return rows;
}

// ------------------------------------------------------------------ headline figures
export function totalRuns(stats: RunStatistics): number {
  return stats.by_type_status.reduce((n, g) => n + g.count, 0);
}

export function finishedRuns(stats: RunStatistics): number {
  return stats.by_type_status.filter((g) => g.status === "completed" || g.status === "partial" || g.status === "failed").reduce((n, g) => n + g.count, 0);
}

export function expiringOrExpired(summary: DashboardSummary): number {
  return summary.validity.now.unique.expiring + summary.validity.now.unique.expired;
}

export type { Dashboard };
