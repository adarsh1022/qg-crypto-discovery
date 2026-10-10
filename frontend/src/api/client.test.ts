import { afterEach, describe, expect, it, vi } from "vitest";
import { errorResponse, installFetch, jsonResponse, listBody, makeRun } from "../test/helpers";
import { ApiError, NetworkError, REQUEST_TIMEOUT_MS, cancelRun, createRun, isAbortError, listRuns } from "./client";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("listRuns", () => {
  it("asks for one page with the filters and offset, using a same-origin URL", async () => {
    const fetchMock = installFetch(() => jsonResponse(listBody([makeRun()])));
    const runs = await listRuns({ type: "filesystem", status: "queued", limit: 50, offset: 100 });
    expect(runs).toHaveLength(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("/api/runs?type=filesystem&status=queued&limit=50&offset=100");
    expect(init?.method).toBe("GET");
    expect(init?.credentials).toBe("same-origin");
    expect(init?.cache).toBe("no-store");
  });

  it("leaves out unset filters and a zero offset", async () => {
    const fetchMock = installFetch(() => jsonResponse(listBody([])));
    await listRuns({ limit: 10 });
    expect(String(fetchMock.mock.calls[0][0])).toBe("/api/runs?limit=10");
  });

  it("rejects an answer that is not a run list", async () => {
    installFetch(() => jsonResponse({ runs: "nope" }));
    await expect(listRuns({ limit: 1 })).rejects.toMatchObject({ code: "invalid_response" });
    installFetch(() => jsonResponse({ runs: [{ run_id: 5 }] }));
    await expect(listRuns({ limit: 1 })).rejects.toMatchObject({ code: "invalid_response" });
    installFetch(() => jsonResponse([1, 2]));
    await expect(listRuns({ limit: 1 })).rejects.toMatchObject({ code: "invalid_response" });
  });
});

describe("errors", () => {
  it("maps the backend's error envelope to an ApiError carrying the fixed code", async () => {
    installFetch(() => errorResponse(422, "invalid_config", "The run configuration is not acceptable.", { field: "max_depth" }));
    const error = await createRun({ type: "filesystem", config: {} }).catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 422, code: "invalid_config", details: { field: "max_depth" } });
  });

  it("never copies a response body into the error message", async () => {
    installFetch(() => new Response("C:\\secret\\path BEGIN CERTIFICATE", { status: 500 }));
    const error = await listRuns({ limit: 1 }).catch((e) => e);
    expect(error).toMatchObject({ status: 500, code: "unknown_error" });
    expect(error.message).not.toMatch(/secret|CERTIFICATE/);
    expect(JSON.stringify(error.details)).toBe("{}");
  });

  it.each([["Bad Code!"], [""], [5], ["x".repeat(80)]])("ignores an error code that is not a fixed identifier (%s)", async (code) => {
    installFetch(() => jsonResponse({ error: { code, message: "m", details: {} } }, 400));
    expect(await listRuns({ limit: 1 }).catch((e) => e)).toMatchObject({ code: "unknown_error" });
  });

  it("treats a failed fetch as unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("Failed to fetch http://127.0.0.1/secret"))));
    const error = await listRuns({ limit: 1 }).catch((e) => e);
    expect(error).toBeInstanceOf(NetworkError);
    expect(error.reason).toBe("unreachable");
    expect(error.message).not.toMatch(/secret/);
  });

  it("gives up after the timeout", async () => {
    vi.useFakeTimers();
    installFetch(() => new Promise<Response>(() => {})); // never answers
    const pending = listRuns({ limit: 1 }).catch((e) => e);
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS + 1);
    expect(await pending).toMatchObject({ reason: "timeout" });
  });

  it("lets the caller's abort through as an AbortError, not a network error", async () => {
    installFetch(() => new Promise<Response>(() => {}));
    const controller = new AbortController();
    const pending = listRuns({ limit: 1 }, controller.signal).catch((e) => e);
    controller.abort();
    const error = await pending;
    expect(isAbortError(error)).toBe(true);
    expect(error).not.toBeInstanceOf(NetworkError);
  });

  it("does not send a request whose signal is already aborted", async () => {
    const fetchMock = installFetch(() => jsonResponse(listBody([])));
    const controller = new AbortController();
    controller.abort();
    expect(isAbortError(await listRuns({ limit: 1 }, controller.signal).catch((e) => e))).toBe(true);
    expect(fetchMock.mock.calls.length === 0 || fetchMock.mock.calls[0][1]?.signal?.aborted).toBe(true);
  });
});

describe("createRun", () => {
  it("posts the filesystem configuration as JSON and returns the run", async () => {
    const created = makeRun({ run_number: 7, status: "queued" });
    const fetchMock = installFetch(() => jsonResponse({ run: created }, 201));
    const run = await createRun({ type: "filesystem", config: { roots: ["C:\\certs"], max_depth: 3 } });
    expect(run.run_number).toBe(7);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("/api/runs");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ type: "filesystem", config: { roots: ["C:\\certs"], max_depth: 3 } });
    expect((init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });

  it("rejects an answer without a run", async () => {
    installFetch(() => jsonResponse({}, 201));
    await expect(createRun({ type: "filesystem", config: {} })).rejects.toMatchObject({ code: "invalid_response" });
  });
});

describe("cancelRun", () => {
  it("posts to the run's cancel URL without a body", async () => {
    const run = makeRun({ run_number: 3, status: "running", cancel_requested: true });
    const fetchMock = installFetch(() => jsonResponse({ run }));
    expect((await cancelRun(run.run_id)).cancel_requested).toBe(true);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe(`/api/runs/${run.run_id}/cancel`);
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeUndefined();
  });

  it.each([["../../etc"], [""], ["A".repeat(32)], ["abc"]])("refuses a malformed run id without sending anything (%s)", async (id) => {
    const fetchMock = installFetch(() => jsonResponse({}));
    await expect(cancelRun(id)).rejects.toThrow("malformed run id");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("surfaces run_not_cancellable", async () => {
    installFetch(() => errorResponse(409, "run_not_cancellable"));
    expect(await cancelRun("a".repeat(32)).catch((e) => e)).toMatchObject({ status: 409, code: "run_not_cancellable" });
  });
});
