import { describe, expect, it } from "vitest";
import { DASH, describeScope, explainStop, formatDuration, formatTime, isWaitingForAgent } from "./format";
import { makeRun, queuedRun } from "./test/helpers";

describe("formatDuration", () => {
  it.each([
    [null, DASH], [undefined, DASH], [-5, DASH], [Number.NaN, DASH],
    [0, "0 ms"], [850, "850 ms"], [1500, "1.5 s"], [12_000, "12 s"], [59_400, "59 s"], [65_000, "1 min 5 s"], [3_660_000, "1 h 1 min"],
  ])("%s -> %s", (input, expected) => {
    expect(formatDuration(input as number | null | undefined)).toBe(expected);
  });
});

describe("formatTime", () => {
  it("shows a dash for a missing time and the raw text for an unreadable one", () => {
    expect(formatTime(null)).toBe(DASH);
    expect(formatTime("")).toBe(DASH);
    expect(formatTime("not a time")).toBe("not a time");
  });
  it("formats a run timestamp", () => {
    const text = formatTime("2026-03-01T12:00:00.000Z");
    expect(text).not.toBe(DASH);
    expect(text).toMatch(/2026|26/);
  });
});

describe("explainStop", () => {
  it("says nothing for runs that are not partial or failed", () => {
    expect(explainStop(makeRun({ status: "completed" }))).toBeNull();
    expect(explainStop(queuedRun(1))).toBeNull();
  });
  it("explains known reasons and shows unknown ones as plain text", () => {
    expect(explainStop(makeRun({ status: "failed", stop_reason: "agent_not_connected" }))).toMatch(/No agent/);
    expect(explainStop(makeRun({ status: "partial", stop_reason: "cancelled" }))).toBe("Cancelled.");
    expect(explainStop(makeRun({ status: "partial", stop_reason: "mystery_code" }))).toBe("mystery_code");
    expect(explainStop(makeRun({ status: "failed", stop_reason: "<b>x</b>" }))).toBe("<b>x</b>");
  });
  it("falls back to the error summary, then to a generic sentence", () => {
    expect(explainStop(makeRun({ status: "failed", stop_reason: null, error_summary: "invalid_config" }))).toMatch(/rejected/);
    expect(explainStop(makeRun({ status: "failed", stop_reason: null, error_summary: null }))).toBe("The run failed.");
    expect(explainStop(makeRun({ status: "partial", stop_reason: null, error_summary: null }))).toBe("The run ended early.");
  });
});

describe("describeScope", () => {
  it("lists the folders, or says the agent's defaults apply", () => {
    expect(describeScope({ roots: ["C:\\a"] })).toBe("C:\\a");
    expect(describeScope({ roots: ["C:\\a", "C:\\b", "C:\\c"] })).toBe("C:\\a (+2 more)");
    expect(describeScope({})).toBe("Agent default locations");
    expect(describeScope({ roots: [] })).toBe(DASH);
    expect(describeScope({ roots: [5, null] })).toBe(DASH);
  });
});

describe("isWaitingForAgent", () => {
  const queued = queuedRun(1, { queued_at: "2026-03-01T12:00:00.000Z" });
  const t0 = Date.parse("2026-03-01T12:00:00.000Z");
  it("is true only for a queued run that has waited more than 20 seconds", () => {
    expect(isWaitingForAgent(queued, t0 + 19_000)).toBe(false);
    expect(isWaitingForAgent(queued, t0 + 21_000)).toBe(true);
    expect(isWaitingForAgent(makeRun({ status: "running" }), t0 + 99_000)).toBe(false);
    expect(isWaitingForAgent({ status: "queued", queued_at: "garbage" }, t0)).toBe(false);
  });
});
