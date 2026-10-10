import type { CreateScheduleBody, Schedule } from "../api/types";
import { errorResponse, jsonResponse, type Req } from "./helpers";

/** A schedule shaped exactly like the backend's ScheduleView (backend/schedule_models.py). */
export function makeSchedule(over: Partial<Schedule> = {}): Schedule {
  return {
    schedule_id: "sched-0000000a",
    run_type: "filesystem",
    interval_seconds: 300,
    config: { roots: ["C:\\certs"] },
    probe_all_listeners: false,
    enabled: true,
    state: "waiting",
    next_due_at: "2026-03-01T12:05:00.000Z",
    created_at: "2026-03-01T12:00:00.000Z",
    last_run: null,
    run_count: 0,
    ...over,
  };
}

export interface ScheduleHooks {
  onCreate?: (body: CreateScheduleBody) => Response | undefined;
  onPatch?: (id: string, body: { enabled: boolean }) => Response | undefined;
  onList?: () => Response | undefined;
}

/**
 * A tiny in-memory /api/schedules: GET, POST and PATCH over `schedules`. It answers only the schedule paths (undefined for
 * anything else) so it can be put in front of the runs fake. `created` and `patched` record what was sent.
 */
export function schedulesBackend(initial: Schedule[], hooks: ScheduleHooks = {}) {
  const schedules = [...initial];
  const created: CreateScheduleBody[] = [];
  const patched: Array<{ id: string; enabled: boolean }> = [];
  let counter = 0x10;

  const handler = (req: Req): Response | undefined => {
    if (req.path === "/api/schedules" && req.method === "GET") return hooks.onList?.() ?? jsonResponse({ schedules });
    if (req.path === "/api/schedules" && req.method === "POST") {
      created.push(req.body);
      const custom = hooks.onCreate?.(req.body);
      if (custom) return custom;
      const enabled = req.body.enabled ?? true;
      const schedule = makeSchedule({
        schedule_id: `sched-${(counter++).toString(16).padStart(8, "0")}`,
        run_type: req.body.run_type,
        interval_seconds: req.body.interval_seconds,
        config: req.body.config as Record<string, unknown>,
        probe_all_listeners: req.body.probe_all_listeners === true,
        enabled,
        state: enabled ? "waiting" : "paused",
        next_due_at: enabled ? "2026-03-01T12:10:00.000Z" : null,
      });
      schedules.push(schedule);
      return jsonResponse({ schedule }, 201);
    }
    const one = /^\/api\/schedules\/([A-Za-z0-9._-]{1,64})$/.exec(req.path);
    if (one && req.method === "PATCH") {
      patched.push({ id: one[1], enabled: req.body.enabled });
      const custom = hooks.onPatch?.(one[1], req.body);
      if (custom) return custom;
      const index = schedules.findIndex((s) => s.schedule_id === one[1]);
      if (index === -1) return errorResponse(404, "schedule_not_found", "No such schedule.");
      const enabled = req.body.enabled as boolean;
      schedules[index] = { ...schedules[index], enabled, state: enabled ? "waiting" : "paused", next_due_at: enabled ? "2026-03-01T12:20:00.000Z" : null };
      return jsonResponse({ schedule: schedules[index] });
    }
    return undefined;
  };
  return { schedules, created, patched, handler };
}
