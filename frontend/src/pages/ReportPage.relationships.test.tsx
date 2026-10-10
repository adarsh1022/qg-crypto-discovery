import { render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Run } from "../api/types";
import { errorResponse, installFetch, makeRun, runningRun } from "../test/helpers";
import { makePresented, makeStoredOn, recorded } from "../test/relationshipFixtures";
import { makeRelationships, makeSummary, reportBackend, type RunData } from "../test/reportBackend";
import { makeTlsSummary } from "../test/tlsFixtures";
import { ReportPage } from "./ReportPage";

afterEach(() => {
  vi.unstubAllGlobals();
});

const urls = (mock: ReturnType<typeof installFetch>) => mock.mock.calls.map(([u]) => String(u));

function show(run: Run, data: RunData, wrap = (h: (r: Parameters<ReturnType<typeof reportBackend>["handler"]>[0]) => Response | Promise<Response>) => h) {
  const be = reportBackend([run], { [run.run_id]: data });
  const fetchMock = installFetch(wrap(be.handler));
  render(<ReportPage runId={run.run_id} />);
  return fetchMock;
}

describe("the Relationships section on a filesystem report", () => {
  const run = makeRun({ run_number: 7, record_count: 3, finding_count: 2 });

  it("lists the run's recorded relationships between the summary and the findings, from this run's own endpoint", async () => {
    const fetchMock = show(run, { summary: makeSummary(run), relationships: recorded(run, [makeStoredOn(1), makeStoredOn(2)]) });
    const section = within((await screen.findByRole("heading", { name: "Relationships" })).closest("section")!);
    expect(await section.findByText(/2 relationships recorded for this run/)).toBeTruthy();
    expect(section.getAllByRole("row")).toHaveLength(3);
    expect(urls(fetchMock)).toContain(`/api/runs/${run.run_id}/relationships`);
    expect(urls(fetchMock).filter((u) => u.includes("/relationships"))).toEqual([`/api/runs/${run.run_id}/relationships`]);
    const order = screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent);
    expect(order.indexOf("Relationships")).toBeGreaterThan(-1);
  });

  it("an older run says 'Not recorded for this run', which is not 'No relationships expected'", async () => {
    show(run, { summary: makeSummary(run), relationships: { ...makeRelationships(run), recording: { state: "incomplete", expected: 2, recorded: 0, missing: 2, unexpected: 0 } } });
    expect(await screen.findByText("Not recorded for this run.")).toBeTruthy();
    expect(screen.queryByText("No relationships expected.")).toBeNull();
  });

  it("a run with nothing to relate says so", async () => {
    show(run, { summary: makeSummary(run) });
    expect(await screen.findByText("No relationships expected.")).toBeTruthy();
  });

  it("a failing relationships request does not break the report or raise an alert", async () => {
    show(run, { summary: makeSummary(run) }, (handler) => (req) => (req.path.endsWith("/relationships") ? errorResponse(503, "busy") : handler(req)));
    expect(await screen.findByText(/Could not load the relationships/)).toBeTruthy();
    expect(await screen.findByRole("heading", { level: 1, name: /Run #7/ })).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("a run that is still running says relationships are not recorded yet", async () => {
    const live = runningRun(8);
    show(live, { summary: makeSummary(live), relationships: makeRelationships(live) });
    expect(await screen.findByText("Not recorded yet.")).toBeTruthy();
  });
});

describe("the Relationships section on a TLS report", () => {
  const run = makeRun({ run_number: 5, type: "tls", config: {}, record_count: 2, finding_count: 2 });

  it("lists listeners and their presented certificates, with process and separate filesystem evidence", async () => {
    const fetchMock = show(run, {
      tlsSummary: makeTlsSummary(run),
      relationships: recorded(run, [makePresented(1), makePresented(2, { process: null })]),
    });
    const section = within((await screen.findByRole("heading", { name: "Relationships" })).closest("section")!);
    expect(await section.findByText(/2 relationships recorded for this run/)).toBeTruthy();
    expect(section.getByRole("columnheader", { name: "Listening process" })).toBeTruthy();
    expect(section.getByText("svc.exe")).toBeTruthy();
    expect(section.getByText("Not determined")).toBeTruthy();
    expect(urls(fetchMock).filter((u) => u.includes("/relationships"))).toEqual([`/api/runs/${run.run_id}/relationships`]);
  });

  it("does not describe an active probe as communication anywhere on the page", async () => {
    show(run, { tlsSummary: makeTlsSummary(run), relationships: recorded(run, [makePresented(1)]) });
    await screen.findByText(/1 relationship recorded for this run/);
    const section = screen.getByRole("heading", { name: "Relationships" }).closest("section")!;
    expect(section.textContent).not.toMatch(/communicat|connected to|traffic between|observed communication/i);
    expect(section.textContent).toMatch(/active probe/);
  });
});
