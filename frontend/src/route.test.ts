import { describe, expect, it } from "vitest";
import { dashboardHref, parseHash, reportHref, runsHref } from "./route";

const ID = "0123456789abcdef0123456789abcdef";

describe("parseHash", () => {
  it.each([[""], ["#"], ["#/"], ["#/runs"], ["#/runs/"], ["#runs"]])("%j is the runs list", (hash) => {
    expect(parseHash(hash)).toEqual({ name: "runs" });
  });

  it.each([["#/dashboard"], ["#/dashboard/"], ["#dashboard"]])("%j is the dashboard", (hash) => {
    expect(parseHash(hash)).toEqual({ name: "dashboard" });
    expect(parseHash(dashboardHref)).toEqual({ name: "dashboard" });
  });

  it.each([["#/dashboard/x"], ["#/Dashboard"], ["#/dashboard?x=1"]])("%j is not the dashboard", (hash) => {
    expect(parseHash(hash)).toEqual({ name: "invalid" });
  });

  it("recognises a run's report", () => {
    expect(parseHash(`#/runs/${ID}`)).toEqual({ name: "report", runId: ID });
    expect(parseHash(`#/runs/${ID}/`)).toEqual({ name: "report", runId: ID });
    expect(parseHash(reportHref(ID))).toEqual({ name: "report", runId: ID });
    expect(parseHash(runsHref)).toEqual({ name: "runs" });
  });

  it.each([
    ["#/runs/abc"], [`#/runs/${ID.toUpperCase()}`], [`#/runs/${ID}x`], [`#/runs/${ID}/extra`], ["#/runs/../etc"], ["#/other"], ["#/runs/%00"],
    [`#/runs/${ID}?x=1`], ["#/runs/<script>"],
  ])("%j is not a valid link", (hash) => {
    expect(parseHash(hash)).toEqual({ name: "invalid" });
  });
});
