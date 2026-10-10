import { act, cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Run } from "../api/types";
import { REPORT_POLL_AFTER_ERROR_MS, REPORT_POLL_MS } from "../hooks/useResource";
import { errorResponse, installFetch, makeRun, runningRun } from "../test/helpers";
import { makeCert, makeSummary, reportBackend, type RunData } from "../test/reportBackend";
import { ReportPage } from "./ReportPage";

let hidden = false;

beforeEach(() => {
  vi.useFakeTimers();
  hidden = false;
  Object.defineProperty(document, "hidden", { configurable: true, get: () => hidden });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  delete (document as unknown as { hidden?: boolean }).hidden;
});

const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const settle = async () => { for (let i = 0; i < 6; i += 1) await advance(0); };
const count = (mock: ReturnType<typeof installFetch>, part: string) => mock.mock.calls.filter(([u]) => String(u).includes(part)).length;
const runGets = (mock: ReturnType<typeof installFetch>, id: string) => mock.mock.calls.filter(([u, i]) => String(u) === `/api/runs/${id}` && (i?.method ?? "GET") === "GET").length;

/** A run whose state the test controls: `set` swaps the run and its report data, as the backend would while a scan progresses. */
function liveRun(initial: Run, data: RunData) {
  const state = { run: initial, data };
  const handler = (req: Parameters<ReturnType<typeof reportBackend>["handler"]>[0]) =>
    reportBackend([state.run], { [state.run.run_id]: state.data }).handler(req);
  return { state, handler };
}

describe("report polling", () => {
  it("follows a running scan: refreshes the run and its sections, keeps the tables on screen, and stops when the run ends", async () => {
    const running = runningRun(1, { record_count: 1, finding_count: 1 });
    const live = liveRun(running, { summary: makeSummary(running, { records: 1, sightings: 1, unique_certificates: 1 }), certs: [makeCert(1)] });
    const fetchMock = installFetch(live.handler);
    render(<ReportPage runId={running.run_id} />);
    await settle();
    expect(screen.getByText("Scan in progress")).toBeTruthy();
    expect(screen.getByRole("button", { name: "CN=host1.example" })).toBeTruthy();
    const initialCerts = count(fetchMock, "/fs/certificates");
    expect(initialCerts).toBe(1);

    // the scan progresses: one more certificate is reported
    const progressed = runningRun(1, { record_count: 2, finding_count: 2 });
    live.state.run = progressed;
    live.state.data = { summary: makeSummary(progressed, { records: 2, sightings: 2, unique_certificates: 2 }), certs: [makeCert(1), makeCert(2)] };
    await advance(REPORT_POLL_MS);
    await settle();
    expect(screen.getByRole("button", { name: "CN=host2.example" })).toBeTruthy();
    expect(screen.queryByText(/Loading/)).toBeNull(); // the old rows stayed while it refreshed
    expect(count(fetchMock, "/fs/certificates")).toBe(2);

    // the scan ends
    const done = makeRun({ run_number: 1, record_count: 2, finding_count: 2 });
    live.state.run = done;
    live.state.data = { summary: makeSummary(done, { records: 2, sightings: 2, unique_certificates: 2 }), certs: [makeCert(1), makeCert(2)] };
    await advance(REPORT_POLL_MS);
    await settle();
    expect(within(screen.getByRole("status", { name: "Run outcome" })).getByText("Completed")).toBeTruthy();
    expect(count(fetchMock, "/fs/certificates")).toBe(3);

    const settled = runGets(fetchMock, running.run_id);
    await advance(REPORT_POLL_MS * 10);
    expect(runGets(fetchMock, running.run_id)).toBe(settled); // finished: no more polling
    expect(count(fetchMock, "/fs/certificates")).toBe(3);
  });

  it("does not poll a run that is already finished", async () => {
    const done = makeRun({ run_number: 1 });
    const fetchMock = installFetch(liveRun(done, { summary: makeSummary(done) }).handler);
    render(<ReportPage runId={done.run_id} />);
    await settle();
    const before = fetchMock.mock.calls.length;
    await advance(60_000);
    expect(fetchMock.mock.calls.length).toBe(before);
  });

  it("pauses while the tab is hidden and refreshes at once when it is visible again", async () => {
    const running = runningRun(1);
    const fetchMock = installFetch(liveRun(running, { summary: makeSummary(running) }).handler);
    render(<ReportPage runId={running.run_id} />);
    await settle();
    expect(runGets(fetchMock, running.run_id)).toBe(1);

    hidden = true;
    document.dispatchEvent(new Event("visibilitychange"));
    await advance(REPORT_POLL_MS * 5);
    expect(runGets(fetchMock, running.run_id)).toBe(1);

    hidden = false;
    document.dispatchEvent(new Event("visibilitychange"));
    await settle();
    expect(runGets(fetchMock, running.run_id)).toBe(2);
    await advance(REPORT_POLL_MS);
    expect(runGets(fetchMock, running.run_id)).toBe(3);
  });

  it("keeps the last state on screen, marked out of date, when a refresh fails, and slows down", async () => {
    const running = runningRun(1, { record_count: 1, finding_count: 1 });
    const live = liveRun(running, { summary: makeSummary(running, { records: 1, sightings: 1 }), certs: [makeCert(1)] });
    let fail = false;
    const fetchMock = installFetch((req) => (fail && req.path === `/api/runs/${running.run_id}` ? errorResponse(503, "busy") : live.handler(req)));
    render(<ReportPage runId={running.run_id} />);
    await settle();
    fail = true;
    await advance(REPORT_POLL_MS);
    await settle();
    expect(screen.getAllByRole("alert")[0].textContent).toMatch(/may be out of date/);
    expect(screen.getByText("Scan in progress")).toBeTruthy(); // still showing the last good state
    expect(screen.getByRole("button", { name: "CN=host1.example" })).toBeTruthy();

    const after = runGets(fetchMock, running.run_id);
    await advance(REPORT_POLL_MS * 2);
    expect(runGets(fetchMock, running.run_id)).toBe(after); // backed off
    await advance(REPORT_POLL_AFTER_ERROR_MS);
    expect(runGets(fetchMock, running.run_id)).toBe(after + 1);
  });

  it("aborts requests that are still in flight when the page is left, and stops polling", async () => {
    const running = runningRun(1);
    let certSignal: AbortSignal | null | undefined;
    const live = liveRun(running, { summary: makeSummary(running) });
    const fetchMock = installFetch((req) => {
      if (!req.path.endsWith("/fs/certificates")) return live.handler(req);
      certSignal = req.signal;
      return new Promise<Response>(() => {}); // the certificate list never answers
    });
    const view = render(<ReportPage runId={running.run_id} />);
    await settle();
    expect(certSignal).toBeTruthy();
    expect(certSignal?.aborted).toBe(false);
    view.unmount();
    expect(certSignal?.aborted).toBe(true);
    const calls = fetchMock.mock.calls.length;
    await advance(REPORT_POLL_MS * 10);
    expect(fetchMock.mock.calls.length).toBe(calls);
  });
});
