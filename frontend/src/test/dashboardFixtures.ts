// Builders and a tiny in-memory backend for the dashboard endpoints (shapes: backend/report_models.py).
import type { Dashboard, DashboardSummary, RunBrief, RunStatistics, TypeStatusCount } from "../api/dashboardTypes";
import type { TlsSummary } from "../api/tlsTypes";
import type { Run } from "../api/types";
import { errorResponse, jsonResponse, type Req } from "./helpers";
import { makeSummary } from "./reportBackend";
import { makeTlsSummary } from "./tlsFixtures";

export function brief(run: Run): RunBrief {
  return { run_id: run.run_id, run_number: run.run_number, type: run.type, status: run.status, started_at: run.started_at, duration_ms: run.duration_ms, record_count: run.record_count, finding_count: run.finding_count };
}

export const makeStats = (groups: TypeStatusCount[], series: RunBrief[] = []): RunStatistics => ({ by_type_status: groups, series });

/** A filesystem summary with the ranked algorithm groups the dashboard charts. */
export function makeDashboardSummary(run: Run, over: Partial<DashboardSummary> = {}): DashboardSummary {
  const base = makeSummary(run, { records: 9, sightings: 9, unique_certificates: 8 }, {
    validity: {
      at_discovery: { valid: 8, expiring: 0, expired: 0, not_yet_valid: 0 },
      now: { unique: { valid: 5, expiring: 2, expired: 1, not_yet_valid: 0 }, sightings: { valid: 6, expiring: 2, expired: 1, not_yet_valid: 0 } },
    },
  });
  return {
    ...base,
    algorithms: {
      top: [
        { key_algorithm: "RSA", key_size: 2048, key_curve: null, unique: 4, sightings: 6 },
        { key_algorithm: "EC", key_size: null, key_curve: "P-256", unique: 2, sightings: 2 },
      ],
      other: { groups: 2, unique: 2, sightings: 2 },
      total_groups: 4,
      limit: 2,
    },
    signature_algorithms: {
      top: [
        { signature_algorithm: "sha256WithRSAEncryption", unique: 6, sightings: 7 },
        { signature_algorithm: "ecdsa-with-SHA256", unique: 2, sightings: 2 },
      ],
      other: null,
      total_groups: 2,
      limit: 10,
    },
    ...over,
  };
}

export function makeDashboard(run: Run | null, over: Partial<Dashboard> = {}): Dashboard {
  return {
    latest_run: run ? brief(run) : null,
    latest_terminal_fs_run: run ? brief(run) : null,
    summary: run ? makeDashboardSummary(run) : null,
    runs_by_status: { queued: 0, running: 0, completed: 0, partial: 0, failed: 0 },
    recent_runs: run ? [brief(run)] : [],
    ...over,
  };
}

export interface DashboardWorld {
  stats?: RunStatistics;
  dashboard?: Dashboard;
  tlsRuns?: Run[];
  tlsSummaries?: Record<string, TlsSummary>;
  /** Endpoints that answer 503 while true (read on every request, so a test can let them recover). */
  failing?: Set<"stats" | "dashboard" | "tlsList" | "tlsSummary">;
}

export function dashboardBackend(world: DashboardWorld) {
  const failing = world.failing ?? new Set();
  const handler = (req: Req): Response | undefined => {
    if (req.method !== "GET") return undefined;
    if (req.path === "/api/runs/stats") return failing.has("stats") ? errorResponse(503, "busy") : jsonResponse(world.stats ?? makeStats([]));
    if (req.path === "/api/dashboard") return failing.has("dashboard") ? errorResponse(503, "busy") : jsonResponse(world.dashboard ?? makeDashboard(null));
    if (req.path === "/api/runs" && req.query.get("type") === "tls") {
      return failing.has("tlsList") ? errorResponse(503, "busy") : jsonResponse({ runs: world.tlsRuns ?? [], limit: Number(req.query.get("limit")), offset: 0 });
    }
    const m = /^\/api\/runs\/([0-9a-f]{32})\/tls\/summary$/.exec(req.path);
    if (m) {
      if (failing.has("tlsSummary")) return errorResponse(503, "busy");
      const run = (world.tlsRuns ?? []).find((r) => r.run_id === m[1]);
      return run ? jsonResponse(world.tlsSummaries?.[m[1]] ?? makeTlsSummary(run)) : errorResponse(404, "run_not_found");
    }
    return undefined;
  };
  return { handler, failing };
}
