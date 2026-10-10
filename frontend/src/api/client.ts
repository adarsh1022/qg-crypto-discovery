// A small typed client for the backend's run API. Same-origin relative URLs only: in development the Vite server proxies
// /api to the loopback backend, so the browser never needs CORS and never talks to another host.
//
// Hygiene: errors carry the HTTP status and the backend's fixed error code, never a response body, and nothing here logs.
import type { RelationshipPage } from "./relationshipTypes";
import type { CertificateDetail, CertificateQuery, Issue, Page, Sighting, SightingQuery, Summary, UniqueCertificate } from "./reportTypes";
import type { TlsObservation, TlsObservationQuery, TlsSummary } from "./tlsTypes";
import type { CreateRunBody, CreateScheduleBody, Run, RunFilters, Schedule } from "./types";

export const REQUEST_TIMEOUT_MS = 15_000;
const RUN_ID = /^[0-9a-f]{32}$/;
const ERROR_CODE = /^[a-z0-9_]{1,64}$/;

/** The backend answered with an error status. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly serverMessage: string; // a fixed sentence from the backend; render as text only
  readonly details: Record<string, unknown>;

  constructor(status: number, code: string, serverMessage = "", details: Record<string, unknown> = {}) {
    super(`backend answered ${status} ${code}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.serverMessage = serverMessage;
    this.details = details;
  }
}

/** The backend could not be reached, did not answer in time, or answered something unusable. */
export class NetworkError extends Error {
  readonly reason: "unreachable" | "timeout";

  constructor(reason: "unreachable" | "timeout") {
    super(`backend ${reason}`);
    this.name = "NetworkError";
    this.reason = reason;
  }
}

export function isAbortError(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { name?: unknown }).name === "AbortError";
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function request(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, REQUEST_TIMEOUT_MS);
  const forward = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener("abort", forward, { once: true });
  }
  try {
    let status: number;
    let ok: boolean;
    let data: unknown = null;
    try {
      const response = await fetch(path, {
        method,
        headers: body === undefined ? { Accept: "application/json" } : { Accept: "application/json", "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: "no-store",
        credentials: "same-origin",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
      });
      status = response.status;
      ok = response.ok;
      try {
        data = await response.json();
      } catch (error) {
        if (controller.signal.aborted) throw error;
        data = null; // not JSON: handled below by status
      }
    } catch (error) {
      if (timedOut) throw new NetworkError("timeout");
      if (signal?.aborted) throw error; // the caller cancelled: let it see the abort
      if (isAbortError(error)) throw error;
      throw new NetworkError("unreachable");
    }
    if (!ok) {
      const envelope = isObject(data) && isObject(data.error) ? data.error : {};
      const code = typeof envelope.code === "string" && ERROR_CODE.test(envelope.code) ? envelope.code : "unknown_error";
      const message = typeof envelope.message === "string" ? envelope.message.slice(0, 300) : "";
      throw new ApiError(status, code, message, isObject(envelope.details) ? envelope.details : {});
    }
    if (!isObject(data)) throw new ApiError(status, "invalid_response");
    return data;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", forward);
  }
}

function asRun(value: unknown): Run {
  if (!isObject(value) || typeof value.run_id !== "string" || typeof value.run_number !== "number" || typeof value.status !== "string") {
    throw new ApiError(200, "invalid_response");
  }
  return value as unknown as Run;
}

function runPath(runId: string, tail = ""): string {
  if (!RUN_ID.test(runId)) throw new Error("malformed run id");
  return `/api/runs/${runId}${tail}`;
}

export interface ListParams extends RunFilters {
  limit: number;
  offset?: number;
}

export async function listRuns(params: ListParams, signal?: AbortSignal): Promise<Run[]> {
  const query = new URLSearchParams();
  if (params.type) query.set("type", params.type);
  if (params.status) query.set("status", params.status);
  query.set("limit", String(params.limit));
  if (params.offset) query.set("offset", String(params.offset));
  const data = await request("GET", `/api/runs?${query}`, undefined, signal);
  if (!Array.isArray(data.runs)) throw new ApiError(200, "invalid_response");
  return data.runs.map(asRun);
}

export async function createRun(body: CreateRunBody, signal?: AbortSignal): Promise<Run> {
  const data = await request("POST", "/api/runs", body, signal);
  return asRun(data.run);
}

export async function cancelRun(runId: string, signal?: AbortSignal): Promise<Run> {
  const data = await request("POST", runPath(runId, "/cancel"), undefined, signal);
  return asRun(data.run);
}

// ------------------------------------------------------------------ schedules
const SCHEDULE_ID = /^[A-Za-z0-9._-]{1,64}$/;

function asSchedule(value: unknown): Schedule {
  if (
    !isObject(value) || typeof value.schedule_id !== "string" || typeof value.run_type !== "string" || typeof value.interval_seconds !== "number" ||
    typeof value.enabled !== "boolean" || typeof value.state !== "string" || !isObject(value.config) || typeof value.run_count !== "number"
  ) {
    throw new ApiError(200, "invalid_response");
  }
  if (value.last_run !== null && (!isObject(value.last_run) || typeof value.last_run.run_id !== "string" || typeof value.last_run.status !== "string")) {
    throw new ApiError(200, "invalid_response");
  }
  return value as unknown as Schedule;
}

export async function listSchedules(signal?: AbortSignal): Promise<Schedule[]> {
  const data = await request("GET", "/api/schedules", undefined, signal);
  if (!Array.isArray(data.schedules)) throw new ApiError(200, "invalid_response");
  return data.schedules.map(asSchedule);
}

export async function createSchedule(body: CreateScheduleBody, signal?: AbortSignal): Promise<Schedule> {
  const data = await request("POST", "/api/schedules", body, signal);
  return asSchedule(data.schedule);
}

/** Pause (false) or resume (true). Nothing else about a schedule can be changed. */
export async function setScheduleEnabled(scheduleId: string, enabled: boolean, signal?: AbortSignal): Promise<Schedule> {
  if (!SCHEDULE_ID.test(scheduleId)) throw new Error("malformed schedule id");
  const data = await request("PATCH", `/api/schedules/${scheduleId}`, { enabled }, signal);
  return asSchedule(data.schedule);
}

// ------------------------------------------------------------------ the filesystem report (read-only)
const SHA256 = /^[0-9a-f]{64}$/;

function query(params: Record<string, string | number | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") q.set(key, String(value));
  }
  const text = q.toString();
  return text ? `?${text}` : "";
}

function asPage<T>(data: Record<string, unknown>): Page<T> {
  if (!Array.isArray(data.items) || typeof data.total !== "number" || typeof data.limit !== "number" || typeof data.offset !== "number") {
    throw new ApiError(200, "invalid_response");
  }
  return data as unknown as Page<T>;
}

export async function getRun(runId: string, signal?: AbortSignal): Promise<Run> {
  return asRun((await request("GET", runPath(runId), undefined, signal)).run);
}

export async function getSummary(runId: string, signal?: AbortSignal): Promise<Summary> {
  const data = await request("GET", runPath(runId, "/fs/summary"), undefined, signal);
  if (!isObject(data.totals) || !isObject(data.run) || !isObject(data.issues) || !isObject(data.validity) || !isObject(data.parse_status)) {
    throw new ApiError(200, "invalid_response");
  }
  return data as unknown as Summary;
}

export async function listCertificates(runId: string, params: CertificateQuery, signal?: AbortSignal): Promise<Page<UniqueCertificate>> {
  return asPage(await request("GET", runPath(runId, `/fs/certificates${query({ ...params })}`), undefined, signal));
}

export async function listObservations(runId: string, params: SightingQuery, signal?: AbortSignal): Promise<Page<Sighting>> {
  return asPage(await request("GET", runPath(runId, `/fs/observations${query({ ...params })}`), undefined, signal));
}

export async function listIssues(runId: string, params: { limit?: number; offset?: number }, signal?: AbortSignal): Promise<Page<Issue>> {
  return asPage(await request("GET", runPath(runId, `/issues${query({ ...params })}`), undefined, signal));
}

export async function getCertificate(sha256: string, signal?: AbortSignal): Promise<CertificateDetail> {
  if (!SHA256.test(sha256)) throw new Error("malformed certificate fingerprint");
  const data = await request("GET", `/api/certificates/${sha256}`, undefined, signal);
  if (typeof data.sha256 !== "string" || !Array.isArray(data.san)) throw new ApiError(200, "invalid_response");
  return data as unknown as CertificateDetail;
}

// ------------------------------------------------------------------ relationships (read-only; both run types)
export async function getRelationships(runId: string, signal?: AbortSignal): Promise<RelationshipPage> {
  const data = await request("GET", runPath(runId, "/relationships"), undefined, signal);
  if (!isObject(data.run) || !isObject(data.recording) || !isObject(data.counts) || !Array.isArray(data.items) || typeof data.total !== "number") {
    throw new ApiError(200, "invalid_response");
  }
  return data as unknown as RelationshipPage;
}

// ------------------------------------------------------------------ the TLS report (read-only)
export async function getTlsSummary(runId: string, signal?: AbortSignal): Promise<TlsSummary> {
  const data = await request("GET", runPath(runId, "/tls/summary"), undefined, signal);
  if (!isObject(data.totals) || !isObject(data.run) || !isObject(data.issues) || !isObject(data.outcomes) || !isObject(data.certificate_validity)) {
    throw new ApiError(200, "invalid_response");
  }
  return data as unknown as TlsSummary;
}

export async function listTlsObservations(runId: string, params: TlsObservationQuery, signal?: AbortSignal): Promise<Page<TlsObservation>> {
  return asPage(await request("GET", runPath(runId, `/tls/observations${query({ ...params })}`), undefined, signal));
}

export async function listTlsIssues(runId: string, params: { limit?: number; offset?: number }, signal?: AbortSignal): Promise<Page<Issue>> {
  return asPage(await request("GET", runPath(runId, `/tls/issues${query({ ...params })}`), undefined, signal));
}
