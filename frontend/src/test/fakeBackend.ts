import type { Run } from "../api/types";
import { errorResponse, jsonResponse, listBody, queuedRun, type Req } from "./helpers";

export interface BackendHooks {
  onCancel?: (id: string) => Response | undefined;
  onCreate?: (body: any) => Response | undefined;
}

/** A tiny in-memory run API: GET/POST /api/runs, GET /api/runs/{id} and POST /api/runs/{id}/cancel over `runs`. */
export function backend(initial: Run[], hooks: BackendHooks = {}) {
  const runs = [...initial];
  const handler = (req: Req): Response => {
    if (req.method === "GET" && req.path === "/api/runs") {
      const limit = Number(req.query.get("limit"));
      const offset = Number(req.query.get("offset") ?? 0);
      const status = req.query.get("status");
      const type = req.query.get("type");
      const matching = runs.filter((r) => (!status || r.status === status) && (!type || r.type === type));
      return jsonResponse(listBody(matching.slice(offset, offset + limit), limit, offset));
    }
    if (req.method === "POST" && req.path === "/api/runs") {
      const custom = hooks.onCreate?.(req.body);
      if (custom) return custom;
      const run = queuedRun(runs.length + 1, { config: req.body.config });
      runs.unshift(run);
      return jsonResponse({ run }, 201);
    }
    if (req.method === "GET" && req.path === "/api/schedules") return jsonResponse({ schedules: [] });      // the page also lists schedules
    const cancel = /^\/api\/runs\/([0-9a-f]{32})\/cancel$/.exec(req.path);
    if (req.method === "POST" && cancel) {
      const custom = hooks.onCancel?.(cancel[1]);
      if (custom) return custom;
      const index = runs.findIndex((r) => r.run_id === cancel[1]);
      runs[index] = runs[index].status === "queued"
        ? { ...runs[index], status: "failed", stop_reason: "cancelled", cancel_requested: true }
        : { ...runs[index], cancel_requested: true };
      return jsonResponse({ run: runs[index] });
    }
    const one = /^\/api\/runs\/([0-9a-f]{32})$/.exec(req.path);
    if (req.method === "GET" && one) {
      const run = runs.find((r) => r.run_id === one[1]);
      return run ? jsonResponse({ run }) : errorResponse(404, "run_not_found", "No such run.");
    }
    return errorResponse(404, "not_found");
  };
  return { runs, handler };
}
