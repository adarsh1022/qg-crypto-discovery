import { afterEach, describe, expect, it, vi } from "vitest";
import { errorResponse, installFetch, jsonResponse, makeRun } from "../test/helpers";
import { makeInconclusive, makeProbe, makeTlsSummary, sha } from "../test/tlsFixtures";
import { ApiError, getTlsSummary, listTlsIssues, listTlsObservations } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

const ID = "cd".repeat(16);
const lastUrl = (mock: ReturnType<typeof installFetch>) => String(mock.mock.calls.at(-1)?.[0]);

describe("TLS report requests", () => {
  it("builds same-origin, read-only URLs for exactly one run", async () => {
    const run = makeRun({ run_number: 1, type: "tls" });
    const mock = installFetch((req) => {
      if (req.path.endsWith("/tls/summary")) return jsonResponse(makeTlsSummary(run));
      return jsonResponse({ items: [], total: 0, limit: 50, offset: 0, frontier: 3 });
    });
    await getTlsSummary(ID);
    expect(lastUrl(mock)).toBe(`/api/runs/${ID}/tls/summary`);
    await listTlsObservations(ID, { outcome: "completed", tls_version: "TLS1.3", process_attribution: "attributed", fingerprint: sha(5), q: "a b", limit: 50, offset: 0, frontier: 9 });
    expect(lastUrl(mock)).toBe(`/api/runs/${ID}/tls/observations?outcome=completed&tls_version=TLS1.3&process_attribution=attributed&fingerprint=${sha(5)}&q=a+b&limit=50&offset=0&frontier=9`);
    await listTlsIssues(ID, { limit: 50, offset: 50 });
    expect(lastUrl(mock)).toBe(`/api/runs/${ID}/tls/issues?limit=50&offset=50`);
    for (const [, init] of mock.mock.calls) expect(init?.method).toBe("GET");
  });

  it("leaves out unset and empty parameters", async () => {
    const mock = installFetch(() => jsonResponse({ items: [], total: 0, limit: 100, offset: 0, frontier: 1 }));
    await listTlsObservations(ID, { q: "", outcome: undefined });
    expect(lastUrl(mock)).toBe(`/api/runs/${ID}/tls/observations`);
  });

  it("refuses a malformed run id without sending anything", async () => {
    const mock = installFetch(() => jsonResponse({}));
    await expect(getTlsSummary("../../x")).rejects.toThrow("malformed run id");
    await expect(listTlsObservations("short", {})).rejects.toThrow("malformed run id");
    await expect(listTlsIssues("A".repeat(32), {})).rejects.toThrow("malformed run id");
    expect(mock).not.toHaveBeenCalled();
  });

  it("returns pages exactly as the backend sent them", async () => {
    installFetch(() => jsonResponse({ items: [makeProbe(0), makeInconclusive(1)], total: 2, limit: 50, offset: 0, frontier: 9 }));
    const page = await listTlsObservations(ID, {});
    expect(page.total).toBe(2);
    expect(page.items[0].handshake_outcome).toBe("completed");
    expect(page.items[1]).toMatchObject({ handshake_outcome: "failed", tls_version: null, peer_certificates: [] });
  });
});

describe("TLS report errors", () => {
  it.each([[404, "run_not_found"], [409, "wrong_run_type"], [422, "validation_failed"], [503, "query_timeout"], [500, "internal_error"]])(
    "maps %i %s to an ApiError", async (status, code) => {
      installFetch(() => errorResponse(status, code));
      const error = await getTlsSummary(ID).catch((e) => e);
      expect(error).toBeInstanceOf(ApiError);
      expect(error).toMatchObject({ status, code });
    });

  it("rejects bodies that are not what the endpoint promises", async () => {
    for (const body of [{}, { totals: {} }, { items: "x" }, []]) {
      installFetch(() => jsonResponse(body));
      await expect(getTlsSummary(ID)).rejects.toMatchObject({ code: "invalid_response" });
    }
    installFetch(() => jsonResponse({ items: [], total: "3", limit: 1, offset: 0 }));
    await expect(listTlsObservations(ID, {})).rejects.toMatchObject({ code: "invalid_response" });
  });
});
