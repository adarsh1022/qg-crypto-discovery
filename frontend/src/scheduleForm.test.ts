import { describe, expect, it } from "vitest";
import { buildScheduleBody, EMPTY_SCHEDULE_FORM, formatInterval, parseInterval, type ScheduleFormValues } from "./scheduleForm";

const form = (over: Partial<ScheduleFormValues> = {}): ScheduleFormValues => ({ ...EMPTY_SCHEDULE_FORM, amount: "5", unit: "minutes", roots: "C:\\certs", ...over });

describe("parseInterval: 15 seconds to 7 days, inclusive, whole numbers", () => {
  it.each([
    ["15", "seconds", 15], ["16", "seconds", 16], ["59", "seconds", 59], ["1", "minutes", 60], ["90", "minutes", 5400], ["1", "hours", 3600],
    ["24", "hours", 86_400], ["1", "days", 86_400], ["7", "days", 604_800], ["168", "hours", 604_800], ["10080", "minutes", 604_800],
    ["604800", "seconds", 604_800], [" 30 ", "seconds", 30], ["0030", "seconds", 30],
  ] as const)("%s %s is %d seconds", (amount, unit, seconds) => {
    expect(parseInterval(amount, unit)).toBe(seconds);
  });

  it.each([
    ["14", "seconds"], ["0", "seconds"], ["0", "days"], ["604801", "seconds"], ["8", "days"], ["169", "hours"], ["10081", "minutes"],
    ["", "minutes"], ["  ", "minutes"], ["1.5", "minutes"], ["1,5", "minutes"], ["-5", "minutes"], ["+5", "minutes"], ["1e2", "seconds"],
    ["abc", "minutes"], ["5 min", "minutes"], ["0x10", "seconds"], ["١٠", "seconds"], ["1234567890", "seconds"],
  ] as const)("refuses %j %s", (amount, unit) => {
    expect(parseInterval(amount, unit)).toMatch(/from 15 seconds to 7 days/);
  });

  it("refuses a unit it does not know", () => {
    expect(parseInterval("5", "fortnights" as never)).toMatch(/from 15 seconds to 7 days/);
  });
});

describe("formatInterval is exact and never rounds", () => {
  it.each([
    [15, "15 s"], [60, "1 min"], [90, "1 min 30 s"], [3600, "1 h"], [3660, "1 h 1 min"], [86_400, "1 day"], [90_000, "1 day 1 h"],
    [604_800, "7 days"], [172_800, "2 days"], [86_461, "1 day 1 min 1 s"], [0, "0 s"],
  ])("%d seconds is %s", (seconds, text) => {
    expect(formatInterval(seconds)).toBe(text);
  });

  it("does not throw on nonsense", () => {
    expect(formatInterval(Number.NaN)).toBe("–");
    expect(formatInterval(-1)).toBe("–");
    expect(formatInterval(Number.POSITIVE_INFINITY)).toBe("–");
  });
});

describe("buildScheduleBody: filesystem", () => {
  it("builds the exact body the backend expects", () => {
    expect(buildScheduleBody(form()).body).toEqual({ run_type: "filesystem", interval_seconds: 300, config: { roots: ["C:\\certs"] } });
  });

  it("never sends the TLS opt-in for a filesystem schedule", () => {
    const body = buildScheduleBody(form({ probeAll: true })).body!;
    expect("probe_all_listeners" in body).toBe(false);
  });

  it("needs folders or the explicit choice of the standard folders, like a one-off scan", () => {
    const empty = buildScheduleBody(form({ roots: "" }));
    expect(empty.body).toBeNull();
    expect(empty.errors.roots).toMatch(/at least one folder/);
    expect(buildScheduleBody(form({ roots: "", useStandardFolders: true })).body).toEqual({ run_type: "filesystem", interval_seconds: 300, config: {} });
  });

  it("refuses relative and network paths", () => {
    expect(buildScheduleBody(form({ roots: "certs\\here" })).errors.roots).toMatch(/absolute local path/);
    expect(buildScheduleBody(form({ roots: "\\\\server\\share" })).errors.roots).toMatch(/UNC/);
  });

  it("reports the interval and the folders at once", () => {
    const result = buildScheduleBody(form({ amount: "1", unit: "seconds", roots: "" }));
    expect(result.body).toBeNull();
    expect(Object.keys(result.errors).sort()).toEqual(["interval", "roots"]);
  });
});

describe("buildScheduleBody: TLS", () => {
  const tls = (over: Partial<ScheduleFormValues> = {}) => form({ kind: "tls", ports: "", roots: "", ...over });

  it("with ports: builds a narrow schedule and no opt-in", () => {
    expect(buildScheduleBody(tls({ ports: "8443, 9443 8443" })).body).toEqual({ run_type: "tls", interval_seconds: 300, config: { ports: [8443, 9443] } });
  });

  it("with no ports and no explicit opt-in: refuses, and builds nothing to send", () => {
    const result = buildScheduleBody(tls());
    expect(result.body).toBeNull();
    expect(result.errors.ports).toMatch(/at least one port, or tick the box/);
  });

  it("with the opt-in: sends it explicitly, with no ports (whatever was typed is ignored)", () => {
    expect(buildScheduleBody(tls({ probeAll: true })).body).toEqual({ run_type: "tls", interval_seconds: 300, config: {}, probe_all_listeners: true });
    expect(buildScheduleBody(tls({ probeAll: true, ports: "443" })).body).toEqual({ run_type: "tls", interval_seconds: 300, config: {}, probe_all_listeners: true });
  });

  it("refuses bad ports", () => {
    for (const ports of ["0", "65536", "80-90", "http"]) expect(buildScheduleBody(tls({ ports })).errors.ports).toMatch(/1 to 65535/);
  });

  it("ignores filesystem folders and never produces a key the backend would not accept", () => {
    const body = buildScheduleBody(tls({ ports: "443", roots: "C:\\certs" })).body!;
    expect(Object.keys(body).sort()).toEqual(["config", "interval_seconds", "run_type"]);
    expect(JSON.stringify(body)).not.toMatch(/roots|host|addr/i);
  });
});
