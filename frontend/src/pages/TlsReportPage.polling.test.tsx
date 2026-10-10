import { act, cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Run } from "../api/types";
import { REPORT_POLL_MS } from "../hooks/useResource";
import { installFetch, makeRun, runningRun } from "../test/helpers";
import { reportBackend, type RunData } from "../test/reportBackend";
import { makeInconclusive, makeProbe, makeTlsSummary } from "../test/tlsFixtures";
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

function liveRun(initial: Run, data: RunData) {
  const state = { run: initial, data };
  const handler = (req: Parameters<ReturnType<typeof reportBackend>["handler"]>[0]) => reportBackend([state.run], { [state.run.run_id]: state.data }).handler(req);
  return { state, handler };
}

describe("TLS report polling", () => {
  it("follows a running probe scan, keeps the table on screen while refreshing, and stops when the run ends", async () => {
    const running = runningRun(1, { type: "tls", config: {}, record_count: 1, finding_count: 1 });
    const live = liveRun(running, { tlsSummary: makeTlsSummary(running, {}, { probe_attempts: 1, handshakes_completed: 1 }), tlsObservations: [makeProbe(0)] });
    const fetchMock = installFetch(live.handler);
    render(<ReportPage runId={running.run_id} />);
    await settle();
    expect(screen.getByText("Scan in progress")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "CN=tls1.example" }).length).toBe(1);
    expect(count(fetchMock, "/tls/observations")).toBe(1);

    const progressed = runningRun(1, { type: "tls", config: {}, record_count: 2, finding_count: 1 });
    live.state.run = progressed;
    live.state.data = { tlsSummary: makeTlsSummary(progressed, {}, { probe_attempts: 2, handshakes_completed: 1, not_completed: 1 }), tlsObservations: [makeProbe(0), makeInconclusive(1)] };
    await advance(REPORT_POLL_MS);
    await settle();
    expect(screen.getByText("Not a TLS finding")).toBeTruthy();                       // the new, inconclusive probe appeared
    expect(screen.queryByText(/Loading/)).toBeNull();                                  // the old rows stayed while it refreshed
    expect(count(fetchMock, "/tls/observations")).toBe(2);

    const done = makeRun({ run_number: 1, type: "tls", config: {}, record_count: 2, finding_count: 1 });
    live.state.run = done;
    live.state.data = { tlsSummary: makeTlsSummary(done, {}, { probe_attempts: 2, handshakes_completed: 1, not_completed: 1 }), tlsObservations: [makeProbe(0), makeInconclusive(1)] };
    await advance(REPORT_POLL_MS);
    await settle();
    expect(within(screen.getByRole("status", { name: "Run outcome" })).getByText("Completed")).toBeTruthy();
    const settled = count(fetchMock, "/tls/summary");
    await advance(REPORT_POLL_MS * 10);
    expect(count(fetchMock, "/tls/summary")).toBe(settled);                           // finished: no more polling
  });

  it("does not poll a finished run, and pauses while the tab is hidden", async () => {
    const done = makeRun({ run_number: 2, type: "tls", config: {} });
    const finishedMock = installFetch(liveRun(done, { tlsSummary: makeTlsSummary(done), tlsObservations: [] }).handler);
    render(<ReportPage runId={done.run_id} />);
    await settle();
    const before = finishedMock.mock.calls.length;
    await advance(60_000);
    expect(finishedMock.mock.calls.length).toBe(before);
    cleanup();

    const running = runningRun(3, { type: "tls", config: {} });
    const mock = installFetch(liveRun(running, { tlsSummary: makeTlsSummary(running), tlsObservations: [] }).handler);
    render(<ReportPage runId={running.run_id} />);
    await settle();
    const runCalls = () => mock.mock.calls.filter(([u, i]) => String(u) === `/api/runs/${running.run_id}` && (i?.method ?? "GET") === "GET").length;
    expect(runCalls()).toBe(1);
    hidden = true;
    document.dispatchEvent(new Event("visibilitychange"));
    await advance(REPORT_POLL_MS * 5);
    expect(runCalls()).toBe(1);
    hidden = false;
    document.dispatchEvent(new Event("visibilitychange"));
    await settle();
    expect(runCalls()).toBe(2);
  });
});
