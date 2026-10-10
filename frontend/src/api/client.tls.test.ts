import { afterEach, describe, expect, it, vi } from "vitest";
import { errorResponse, installFetch, jsonResponse, makeRun } from "../test/helpers";
import { createRun } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("createRun for a TLS scan", () => {
  it("posts exactly the TLS body to the same endpoint as a filesystem scan and returns the run", async () => {
    const created = makeRun({ run_number: 3, type: "tls", status: "queued", config: { ports: [8443] } });
    const fetchMock = installFetch(() => jsonResponse({ run: created }, 201));
    const run = await createRun({ type: "tls", config: { ports: [8443], time_budget_seconds: 30 } });
    expect(run.type).toBe("tls");
    expect(run.run_number).toBe(3);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("/api/runs");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ type: "tls", config: { ports: [8443], time_budget_seconds: 30 } });
    expect((init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });

  it("never adds a trigger or a schedule: a scan started from the page is always a manual run", async () => {
    const fetchMock = installFetch(() => jsonResponse({ run: makeRun({ type: "tls" }) }, 201));
    await createRun({ type: "tls", config: {} });
    const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body));
    expect(Object.keys(body).sort()).toEqual(["config", "type"]);
  });

  it("passes the backend's refusal of an unknown key through as an ApiError with its fixed code", async () => {
    installFetch(() => errorResponse(422, "invalid_config", "The run configuration is not acceptable.", { problem: "unknown_key", allowed_keys: ["ports"] }));
    await expect(createRun({ type: "tls", config: {} })).rejects.toMatchObject({ status: 422, code: "invalid_config" });
  });
});
