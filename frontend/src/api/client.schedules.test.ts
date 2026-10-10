import { afterEach, describe, expect, it, vi } from "vitest";
import { errorResponse, installFetch, jsonResponse } from "../test/helpers";
import { makeSchedule } from "../test/scheduleHelpers";
import { ApiError, createSchedule, listSchedules, setScheduleEnabled } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("listSchedules", () => {
  it("asks for /api/schedules with a same-origin GET and returns the schedules as they came", async () => {
    const one = makeSchedule({ last_run: { run_id: "a".repeat(32), run_number: 4, status: "running", queued_at: "2026-03-01T12:05:00.000Z", finished_at: null }, run_count: 4 });
    const fetchMock = installFetch(() => jsonResponse({ schedules: [one] }));
    expect(await listSchedules()).toEqual([one]);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("/api/schedules");
    expect(init?.method).toBe("GET");
    expect(init?.credentials).toBe("same-origin");
    expect(init?.cache).toBe("no-store");
  });

  it.each([
    [{ schedules: "nope" }], [{}], [[1]], [{ schedules: [{ schedule_id: 5 }] }], [{ schedules: [{ ...makeSchedule(), enabled: "yes" }] }],
    [{ schedules: [{ ...makeSchedule(), config: [] }] }], [{ schedules: [{ ...makeSchedule(), last_run: { run_id: 1 } }] }],
    [{ schedules: [{ ...makeSchedule(), run_count: "3" }] }],
  ])("rejects an answer that is not a schedule list (%#)", async (body) => {
    installFetch(() => jsonResponse(body));
    await expect(listSchedules()).rejects.toMatchObject({ code: "invalid_response" });
  });
});

describe("createSchedule", () => {
  it("posts exactly the body it was given, as JSON, and returns the schedule", async () => {
    const created = makeSchedule({ schedule_id: "sched-12345678", run_type: "tls", config: {}, probe_all_listeners: true });
    const fetchMock = installFetch(() => jsonResponse({ schedule: created }, 201));
    const body = { run_type: "tls" as const, interval_seconds: 30, config: {}, probe_all_listeners: true };
    expect(await createSchedule(body)).toEqual(created);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("/api/schedules");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual(body);
    expect((init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });

  it("rejects an answer without a schedule", async () => {
    installFetch(() => jsonResponse({}, 201));
    await expect(createSchedule({ run_type: "filesystem", interval_seconds: 60, config: {} })).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("carries the backend's refusal, with its fixed code and the field it named", async () => {
    installFetch(() => errorResponse(422, "invalid_schedule", "The schedule is not acceptable.", { field: "interval_seconds", problem: "out_of_range" }));
    const error = await createSchedule({ run_type: "filesystem", interval_seconds: 5, config: {} }).catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 422, code: "invalid_schedule", details: { field: "interval_seconds" } });
  });
});

describe("setScheduleEnabled", () => {
  it("patches only the enabled flag, at the schedule's own path", async () => {
    const paused = makeSchedule({ enabled: false, state: "paused", next_due_at: null });
    const fetchMock = installFetch(() => jsonResponse({ schedule: paused }));
    expect(await setScheduleEnabled("sched-0000000a", false)).toEqual(paused);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("/api/schedules/sched-0000000a");
    expect(init?.method).toBe("PATCH");
    expect(JSON.parse(String(init?.body))).toEqual({ enabled: false });
  });

  it("refuses an id that could change the path, before any request is made", async () => {
    const fetchMock = installFetch(() => jsonResponse({ schedule: makeSchedule() }));
    for (const id of ["", "../runs", "a/b", "sched 1", "x".repeat(65), "sched-1?x=1", "sched-1#"]) {
      await expect(setScheduleEnabled(id, true)).rejects.toThrow("malformed schedule id");
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("passes a 404 through as an ApiError", async () => {
    installFetch(() => errorResponse(404, "schedule_not_found", "No such schedule."));
    await expect(setScheduleEnabled("sched-0000000a", true)).rejects.toMatchObject({ status: 404, code: "schedule_not_found" });
  });
});
