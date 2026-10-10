import { afterEach, describe, expect, it, vi } from "vitest";
import { errorResponse, installFetch, jsonResponse, makeRun } from "../test/helpers";
import { makeCert, makeDetail, makeIssue, makeSighting, makeSummary, sha } from "../test/reportBackend";
import { ApiError, getCertificate, getRun, getSummary, listCertificates, listIssues, listObservations } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

const ID = "ab".repeat(16);
const lastUrl = (mock: ReturnType<typeof installFetch>) => String(mock.mock.calls.at(-1)?.[0]);

describe("report requests", () => {
  it("builds same-origin URLs for exactly one run", async () => {
    const run = makeRun({ run_number: 1 });
    const mock = installFetch((req) => {
      if (req.path.endsWith("/fs/summary")) return jsonResponse(makeSummary(run));
      if (req.path.endsWith("/issues")) return jsonResponse({ items: [makeIssue()], total: 1, limit: 50, offset: 0 });
      return jsonResponse({ items: [], total: 0, limit: 50, offset: 0, frontier: 3 });
    });
    await getSummary(ID);
    expect(lastUrl(mock)).toBe(`/api/runs/${ID}/fs/summary`);
    await listCertificates(ID, { sort: "not_after", direction: "asc", limit: 50, offset: 100, frontier: 7 });
    expect(lastUrl(mock)).toBe(`/api/runs/${ID}/fs/certificates?sort=not_after&direction=asc&limit=50&offset=100&frontier=7`);
    await listObservations(ID, { q: "a b", parse_status: "no_certificate", fingerprint: sha(5), limit: 10, offset: 0 });
    expect(lastUrl(mock)).toBe(`/api/runs/${ID}/fs/observations?q=a+b&parse_status=no_certificate&fingerprint=${sha(5)}&limit=10&offset=0`);
    await listIssues(ID, { limit: 50, offset: 50 });
    expect(lastUrl(mock)).toBe(`/api/runs/${ID}/issues?limit=50&offset=50`);
    for (const [, init] of mock.mock.calls) expect(init?.method).toBe("GET");
  });

  it("leaves out unset and empty parameters", async () => {
    const mock = installFetch(() => jsonResponse({ items: [], total: 0, limit: 100, offset: 0, frontier: 1 }));
    await listObservations(ID, { q: "", parse_status: undefined });
    expect(lastUrl(mock)).toBe(`/api/runs/${ID}/fs/observations`);
  });

  it("refuses a malformed run id or fingerprint without sending anything", async () => {
    const mock = installFetch(() => jsonResponse({}));
    await expect(getSummary("../../x")).rejects.toThrow("malformed run id");
    await expect(listIssues("short", {})).rejects.toThrow("malformed run id");
    await expect(getCertificate("zz")).rejects.toThrow("malformed certificate fingerprint");
    await expect(getCertificate(sha(1) + "0")).rejects.toThrow("malformed certificate fingerprint");
    expect(mock).not.toHaveBeenCalled();
  });

  it("reads a run, a certificate and its detail", async () => {
    const run = makeRun({ run_number: 4 });
    installFetch((req) => (req.path.startsWith("/api/certificates/") ? jsonResponse(makeDetail(1)) : jsonResponse({ run })));
    expect((await getRun(run.run_id)).run_number).toBe(4);
    expect((await getCertificate(sha(1))).serial_hex).toBe("0a1b2c3d");
  });

  it("returns the page as the backend sent it", async () => {
    installFetch(() => jsonResponse({ items: [makeCert(1)], total: 1, limit: 50, offset: 0, frontier: 9 }));
    const page = await listCertificates(ID, {});
    expect(page).toMatchObject({ total: 1, frontier: 9 });
    expect(page.items[0].subject).toBe("CN=host1.example");
    installFetch(() => jsonResponse({ items: [makeSighting(0)], total: 1, limit: 100, offset: 0, frontier: 9 }));
    expect((await listObservations(ID, {})).items[0].path).toContain("file0.pem");
  });
});

describe("report errors", () => {
  it.each([
    [404, "run_not_found"], [409, "wrong_run_type"], [503, "query_timeout"], [422, "validation_failed"], [500, "internal_error"],
  ])("maps %i %s to an ApiError", async (status, code) => {
    installFetch(() => errorResponse(status, code));
    const error = await getSummary(ID).catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status, code });
  });

  it("rejects bodies that are not what the endpoint promises", async () => {
    for (const body of [{}, { totals: {} }, { items: "x" }, []]) {
      installFetch(() => jsonResponse(body));
      await expect(getSummary(ID)).rejects.toMatchObject({ code: "invalid_response" });
    }
    installFetch(() => jsonResponse({ items: [], total: "3", limit: 1, offset: 0 }));
    await expect(listCertificates(ID, {})).rejects.toMatchObject({ code: "invalid_response" });
    installFetch(() => jsonResponse({ sha256: sha(1) }));
    await expect(getCertificate(sha(1))).rejects.toMatchObject({ code: "invalid_response" });
  });
});
