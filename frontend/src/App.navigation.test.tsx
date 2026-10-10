import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { POLL_MS } from "./hooks/useRunList";
import { installFetch, makeRun, queuedRun, runningRun } from "./test/helpers";
import { makeCert, makeSummary, reportBackend, type RunData } from "./test/reportBackend";

beforeEach(() => {
  window.location.hash = "";
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  window.location.hash = "";
});

const rowFor = (n: number) => screen.getByRole("row", { name: new RegExp(`^#${n}\\b`) });

function setup(runs = [
  makeRun({ run_number: 5, status: "failed", error_summary: "no_usable_data", record_count: 0, finding_count: 0 }),
  runningRun(4),
  queuedRun(3),
  makeRun({ run_number: 2, status: "partial", error_summary: "file_errors:1", record_count: 1, finding_count: 1 }),
  makeRun({ run_number: 1 }),
]) {
  const data: Record<string, RunData> = Object.fromEntries(runs.map((r) => [r.run_id, { summary: makeSummary(r), certs: [makeCert(r.run_number)] }]));
  const be = reportBackend(runs, data);
  const fetchMock = installFetch(be.handler);
  const user = userEvent.setup();
  return { be, fetchMock, user, runs };
}

describe("opening a report from the runs list", () => {
  // Changed with the TLS report (this test used to assert that TLS runs have no report and no link). A TLS run now gets a link to
  // ITS report, labelled as a TLS report; filesystem links are unchanged and a queued run still has none.
  it("offers a Report link on runs that have started, labelled by type, and not on queued runs", async () => {
    const tls = makeRun({ run_number: 6, type: "tls" });
    const s = setup([tls, queuedRun(3), runningRun(4), makeRun({ run_number: 1 }), makeRun({ run_number: 7, type: "tls", status: "queued", started_at: null })]);
    render(<App />);
    await screen.findByRole("table");
    expect(within(rowFor(1)).getByRole("link", { name: "Open report for run 1" }).getAttribute("href")).toBe(`#/runs/${s.runs[3].run_id}`);
    expect(within(rowFor(4)).getByRole("link", { name: "Open report for run 4" })).toBeTruthy(); // running: results so far
    expect(within(rowFor(3)).queryByRole("link")).toBeNull(); // queued: nothing to report yet
    const tlsLink = within(rowFor(6)).getByRole("link", { name: "Open TLS report for run 6" });
    expect(tlsLink.getAttribute("href")).toBe(`#/runs/${s.runs[0].run_id}`); // the one report route; the page picks the view by run type
    expect(within(rowFor(6)).queryByRole("link", { name: "Open report for run 6" })).toBeNull(); // never labelled as a filesystem report
    expect(within(rowFor(7)).queryByRole("link")).toBeNull(); // a queued TLS run has nothing to report yet either
  });

  it("opens that run's report, and every report request is for that run", async () => {
    const s = setup();
    render(<App />);
    await screen.findByRole("table");
    await s.user.click(within(rowFor(2)).getByRole("link", { name: "Open report for run 2" }));
    expect(await screen.findByRole("heading", { level: 1, name: /Run #2/ })).toBeTruthy();
    expect(window.location.hash).toBe(`#/runs/${s.runs[3].run_id}`);
    await screen.findByRole("table", { name: /Unique certificates/ });
    const reportCalls = s.fetchMock.mock.calls.map(([u]) => String(u)).filter((u) => u.includes("/fs/") || u.includes("/issues"));
    expect(reportCalls.length).toBeGreaterThan(0);
    for (const u of reportCalls) expect(u).toContain(s.runs[3].run_id);
  });

  it("loads a report straight from its link", async () => {
    const s = setup();
    window.location.hash = `#/runs/${s.runs[4].run_id}`;
    render(<App />);
    expect(await screen.findByRole("heading", { level: 1, name: /Run #1/ })).toBeTruthy();
  });

  it("rejects a link that is not a run id", async () => {
    setup();
    window.location.hash = "#/runs/not-a-run";
    render(<App />);
    expect(await screen.findByText("That is not a valid run link.")).toBeTruthy();
    expect(screen.getByRole("link", { name: "← Discovery runs" }).getAttribute("href")).toBe("#/runs");
  });
});

describe("returning to the runs list", () => {
  it("brings the user back to the list as they left it: filter and loaded rows intact", async () => {
    const s = setup();
    render(<App />);
    await screen.findByRole("table");
    await s.user.selectOptions(screen.getByLabelText(/Status/), "completed");
    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(2)); // header + run #1
    await s.user.click(within(rowFor(1)).getByRole("link", { name: "Open report for run 1" }));
    await screen.findByRole("heading", { level: 1, name: /Run #1/ });
    expect(screen.queryByRole("table", { name: /Discovery runs/ })).toBeNull(); // the list is hidden, not shown under the report

    await s.user.click(screen.getByRole("link", { name: "← Discovery runs" }));
    await waitFor(() => expect(window.location.hash).toBe("#/runs"));
    expect((screen.getByLabelText(/Status/) as HTMLSelectElement).value).toBe("completed");
    expect(rowFor(1)).toBeTruthy();
    expect(screen.queryByRole("heading", { level: 1, name: /Run #1 filesystem report/ })).toBeNull();
  });

  it("has a back link on the report that points to the runs list", async () => {
    const s = setup();
    window.location.hash = `#/runs/${s.runs[4].run_id}`;
    render(<App />);
    await screen.findByRole("heading", { level: 1, name: /Run #1/ });
    const links = screen.getAllByRole("link", { name: /Discovery runs/ });
    expect(links.every((l) => l.getAttribute("href") === "#/runs")).toBe(true);
  });
});

describe("the runs list does not poll while a report is open", () => {
  it("pauses behind the report and refreshes at once on return", async () => {
    vi.useFakeTimers();
    const s = setup([runningRun(4), makeRun({ run_number: 1 })]);
    const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
    const listCalls = () => s.fetchMock.mock.calls.filter(([u]) => String(u).startsWith("/api/runs?")).length;

    render(<App />);
    await advance(0);
    await advance(0);
    expect(listCalls()).toBe(1);
    await advance(POLL_MS);
    expect(listCalls()).toBe(2); // polling while the list is visible and a run is active

    await act(async () => { window.location.hash = `#/runs/${s.runs[1].run_id}`; });
    await advance(0);
    await advance(0);
    const hiddenAt = listCalls();
    await advance(POLL_MS * 5);
    expect(listCalls()).toBe(hiddenAt); // paused behind the report

    await act(async () => { window.location.hash = "#/runs"; });
    await advance(0);
    await advance(0);
    expect(listCalls()).toBe(hiddenAt + 1); // refreshed when the list came back
    await advance(POLL_MS);
    expect(listCalls()).toBe(hiddenAt + 2); // and polling resumed
  });
});
