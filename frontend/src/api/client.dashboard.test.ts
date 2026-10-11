import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, getDashboard, getRunStatistics } from "./client";
import { errorResponse, installFetch, jsonResponse, makeRun } from "../test/helpers";
import { makeDashboard, makeStats } from "../test/dashboardFixtures";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("getRunStatistics", () => {
  it("is a GET of /api/runs/stats and returns the counts and series as sent", async () => {
    const stats = makeStats([{ type: "tls", status: "completed", count: 2 }]);
    const fetchMock = installFetch(() => jsonResponse(stats));
    expect(await getRunStatistics()).toEqual(stats);
    expect(fetchMock.mock.calls.map(([u, i]) => [String(u), i?.method ?? "GET"])).toEqual([["/api/runs/stats", "GET"]]);
  });

  it.each([[{ by_type_status: "x", series: [] }], [{ series: [] }], [{ by_type_status: [] }]])("refuses an answer it does not understand (%j)", async (body) => {
    installFetch(() => jsonResponse(body));
    await expect(getRunStatistics()).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("surfaces the backend's error code", async () => {
    installFetch(() => errorResponse(503, "busy"));
    await expect(getRunStatistics()).rejects.toBeInstanceOf(ApiError);
  });
});

describe("getDashboard", () => {
  it("is a GET of /api/dashboard", async () => {
    const dashboard = makeDashboard(makeRun({ run_number: 2 }));
    const fetchMock = installFetch(() => jsonResponse(dashboard));
    expect(await getDashboard()).toEqual(dashboard);
    expect(fetchMock.mock.calls.map(([u, i]) => [String(u), i?.method ?? "GET"])).toEqual([["/api/dashboard", "GET"]]);
  });

  it("accepts a database with no finished filesystem run (summary and run are null)", async () => {
    installFetch(() => jsonResponse(makeDashboard(null)));
    expect(await getDashboard()).toMatchObject({ summary: null, latest_terminal_fs_run: null });
  });

  it.each([[{}], [{ runs_by_status: {}, recent_runs: [] }], [{ runs_by_status: "x", recent_runs: [], summary: null, latest_terminal_fs_run: null }]])(
    "refuses an answer it does not understand (%j)", async (body) => {
      installFetch(() => jsonResponse(body));
      await expect(getDashboard()).rejects.toMatchObject({ code: "invalid_response" });
    },
  );
});
