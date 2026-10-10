import { vi } from "vitest";
import type { Run } from "../api/types";

/** A run shaped exactly like the backend's RunView (backend/api_models.py). */
export function makeRun(over: Partial<Run> = {}): Run {
  const number = over.run_number ?? 1;
  return {
    run_id: number.toString(16).padStart(32, "0"),
    run_number: number,
    type: "filesystem",
    trigger: "manual",
    schedule_id: null,
    status: "completed",
    config: { roots: ["C:\\certs"] },
    host_id: null,
    queued_at: "2026-03-01T12:00:00.000Z",
    started_at: "2026-03-01T12:00:01.000Z",
    finished_at: "2026-03-01T12:00:11.000Z",
    last_heartbeat_at: null,
    duration_ms: 10_000,
    stop_reason: "completed",
    cancel_requested: false,
    cancel_requested_at: null,
    record_count: 8,
    finding_count: 6,
    rejected_count: 0,
    error_count: 0,
    error_summary: null,
    agent_summary: null,
    ...over,
  };
}

export const queuedRun = (n: number, over: Partial<Run> = {}) =>
  makeRun({ run_number: n, status: "queued", started_at: null, finished_at: null, duration_ms: null, stop_reason: null, record_count: 0, finding_count: 0, ...over });
export const runningRun = (n: number, over: Partial<Run> = {}) =>
  makeRun({ run_number: n, status: "running", finished_at: null, duration_ms: null, stop_reason: null, ...over });

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

export function errorResponse(status: number, code: string, message = "A fixed sentence.", details: Record<string, unknown> = {}): Response {
  return jsonResponse({ error: { code, message, details } }, status);
}

export interface Req {
  method: string;
  path: string; // without the query string
  query: URLSearchParams;
  body: any;
  signal: AbortSignal | null | undefined;
}

export type Handler = (req: Req) => Response | Promise<Response>;

/** Replace fetch with a handler. Requests whose signal aborts reject with an AbortError, like the real thing. */
export function installFetch(handler: Handler) {
  const mock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://127.0.0.1:5173");
    const req: Req = {
      method: init?.method ?? "GET",
      path: url.pathname,
      query: url.searchParams,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
      signal: init?.signal,
    };
    return new Promise<Response>((resolve, reject) => {
      const abort = () => reject(new DOMException("aborted", "AbortError"));
      if (init?.signal?.aborted) return abort();
      init?.signal?.addEventListener("abort", abort, { once: true });
      Promise.resolve(handler(req)).then(resolve, reject);
    });
  });
  vi.stubGlobal("fetch", mock);
  return mock;
}

export const listBody = (runs: Run[], limit = 50, offset = 0) => ({ runs, limit, offset });
