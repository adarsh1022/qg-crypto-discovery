import { describe, expect, it } from "vitest";
import { describeOutcome, explainRun, explainStop, explainToken, wasCancelled } from "./format";
import { makeRun, queuedRun } from "./test/helpers";

// What the backend really records (backend/run_state.decide_outcome): a failed or partial run whose scan itself ran to the end
// has stop_reason "completed", and the actual cause is in error_summary.
describe("explainRun: the real reason comes from error_summary", () => {
  it("explains a failed run instead of echoing stop_reason 'completed'", () => {
    const run = makeRun({ status: "failed", stop_reason: "completed", error_summary: "no_usable_data, roots_not_scanned:1, file_errors:1" });
    expect(explainRun(run)).toEqual(["No usable results were produced.", "1 folder could not be scanned.", "1 read error was recorded."]);
    expect(explainStop(run)).not.toBe("completed");
    expect(describeOutcome(run)).toBe("No usable results were produced. 1 folder could not be scanned. 1 read error was recorded.");
  });

  it("explains a partial run, with plurals", () => {
    const run = makeRun({ status: "partial", stop_reason: "completed", error_summary: "roots_not_scanned:2, file_errors:3, records_rejected:1, seq_conflicts:2, bundles_truncated:1" });
    expect(explainRun(run)).toEqual([
      "2 folders could not be scanned.", "3 read errors were recorded.", "1 record was rejected by the backend.",
      "2 uploads conflicted with data already stored.", "1 certificate bundle was cut short.",
    ]);
  });

  it.each([
    ["stopped_cancelled", "The scan was cancelled before it finished."],
    ["stopped_time_limit", "The scan hit its time budget and stopped early."],
    ["stopped_node_limit", "The scan stopped early (node_limit)."],
    ["agent_lost", "The agent stopped responding."],
    ["count_mismatch", "The agent's record count did not match what the backend stored."],
    ["stop_reason_missing", "The agent did not say why it stopped."],
    ["invalid_config", "The agent rejected the scan settings."],
    ["agent_not_connected", "No agent picked up the run in time."],
    ["cancelled", "Cancelled."],
  ])("translates the token %s", (token, sentence) => {
    expect(explainToken(token)).toBe(sentence);
    expect(explainRun(makeRun({ status: "partial", stop_reason: "completed", error_summary: token }))).toEqual([sentence]);
  });

  it("keeps unknown tokens as plain text and never throws", () => {
    expect(explainToken("something_new")).toBe("something_new");
    expect(explainToken("something_new:7")).toBe("something_new:7");
    expect(explainToken("<img src=x>")).toBe("<img src=x>");
    expect(explainToken("roots_not_scanned:99999999999")).toBe("roots_not_scanned:99999999999");
    expect(explainRun(makeRun({ status: "failed", stop_reason: "completed", error_summary: "mystery, file_errors:2" }))).toEqual(["mystery", "2 read errors were recorded."]);
  });

  it("falls back to stop_reason only when there is no summary and it is not the clean 'completed'", () => {
    expect(explainRun(makeRun({ status: "partial", stop_reason: "cancelled", error_summary: null }))).toEqual(["Cancelled."]);
    expect(explainRun(makeRun({ status: "failed", stop_reason: "completed", error_summary: null }))).toEqual(["The run failed."]);
    expect(explainRun(makeRun({ status: "partial", stop_reason: null, error_summary: "" }))).toEqual(["The run ended early."]);
  });

  it("explains nothing for runs that are not partial or failed", () => {
    for (const status of ["completed", "queued", "running"]) {
      expect(explainRun(makeRun({ status, error_summary: "file_errors:1" }))).toEqual([]);
    }
  });
});

describe("the shared file_errors token is worded by run type", () => {
  it("a TLS run counts scan errors, never read errors", () => {
    expect(explainToken("file_errors:1", "tls")).toBe("1 scan error was recorded.");
    expect(explainToken("file_errors:3", "tls")).toBe("3 scan errors were recorded.");
    const run = makeRun({ type: "tls", status: "partial", stop_reason: "completed", error_summary: "file_errors:2, stopped_target_limit" });
    expect(explainRun(run)).toEqual(["2 scan errors were recorded.", "The target limit was reached, so not every listener was probed."]);
    expect(describeOutcome(run)).not.toMatch(/read error/);
    expect(explainStop(run)).not.toMatch(/read error/);
  });

  it("filesystem wording is unchanged, with or without a type", () => {
    expect(explainToken("file_errors:1", "filesystem")).toBe("1 read error was recorded.");
    expect(explainToken("file_errors:3")).toBe("3 read errors were recorded.");
    expect(explainRun(makeRun({ type: "filesystem", status: "partial", stop_reason: "completed", error_summary: "file_errors:2" }))).toEqual(["2 read errors were recorded."]);
  });

  it("only changes file_errors: the other shared tokens read the same for both types", () => {
    for (const token of ["records_rejected:2", "seq_conflicts:1", "roots_not_scanned:1", "bundles_truncated:1", "agent_lost", "count_mismatch"]) {
      expect(explainToken(token, "tls")).toBe(explainToken(token, "filesystem"));
    }
  });

  it("a token named like an object property is kept as text, not looked up on the prototype", () => {
    expect(explainToken("constructor:3", "tls")).toBe("constructor:3");
    expect(explainToken("toString:1")).toBe("toString:1");
  });

  it("passes the run's own type for every token, not the array index", () => {
    const run = makeRun({ type: "tls", status: "failed", stop_reason: "completed", error_summary: "no_usable_data, file_errors:1, file_errors:2" });
    expect(explainRun(run)).toEqual(["No usable results were produced.", "1 scan error was recorded.", "2 scan errors were recorded."]);
  });
});

describe("describeOutcome", () => {
  it("separates a completed run that reported no records from one that found something", () => {
    expect(describeOutcome(makeRun({ status: "completed", record_count: 0 }))).toBe("Completed, but the agent reported no records.");
    expect(describeOutcome(makeRun({ status: "completed", record_count: 1 }))).toBe("Finished normally.");
  });
  it("does not claim that no certificate files existed", () => {
    expect(describeOutcome(makeRun({ status: "completed", record_count: 0 }))).not.toMatch(/no certificate files|nothing exists|no files/i);
  });
  it("says nothing for active runs", () => {
    expect(describeOutcome(queuedRun(1))).toBeNull();
    expect(describeOutcome(makeRun({ status: "running" }))).toBeNull();
  });
});

describe("wasCancelled", () => {
  it("recognises both ways the backend records a cancellation", () => {
    expect(wasCancelled(makeRun({ status: "failed", stop_reason: "cancelled", error_summary: "cancelled" }))).toBe(true);
    expect(wasCancelled(makeRun({ status: "partial", stop_reason: "cancelled", error_summary: "stopped_cancelled" }))).toBe(true);
    expect(wasCancelled(makeRun({ status: "partial", stop_reason: "completed", error_summary: "file_errors:1" }))).toBe(false);
  });
});
