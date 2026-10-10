import { act, cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { POLL_AFTER_ERROR_MS, POLL_MS } from "../hooks/useRunList";
import { RunsPage } from "./RunsPage";
import { errorResponse, installFetch, jsonResponse, listBody, makeRun, queuedRun, runningRun, type Req } from "../test/helpers";

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
// The page also lists schedules (its own request, polled on its own). These tests are about the RUNS list, so that request is
// answered separately here and is not counted; every assertion below is about /api/runs exactly as before.
const serve = (handler: (req: Req) => Response | Promise<Response>) =>
  installFetch((req) => (req.path === "/api/schedules" ? jsonResponse({ schedules: [] }) : handler(req)));
const listCalls = (mock: ReturnType<typeof installFetch>) =>
  mock.mock.calls.filter(([url, i]) => (i?.method ?? "GET") === "GET" && String(url).startsWith("/api/runs")).length;
const flush = () => advance(0);
const badge = () => within(screen.getByRole("row", { name: /^#1/ }));

describe("polling", () => {
  it("polls while a run is queued or running and stops once nothing is active", async () => {
    let current = [runningRun(1)];
    const fetchMock = serve(() => jsonResponse(listBody(current)));
    render(<RunsPage />);
    await flush();
    expect(listCalls(fetchMock)).toBe(1);

    await advance(POLL_MS);
    expect(listCalls(fetchMock)).toBe(2);
    await advance(POLL_MS);
    expect(listCalls(fetchMock)).toBe(3);

    current = [makeRun({ run_number: 1 })]; // the scan ends
    await advance(POLL_MS);
    expect(listCalls(fetchMock)).toBe(4);
    expect(badge().getByText("Completed")).toBeTruthy();

    await advance(POLL_MS * 10);
    expect(listCalls(fetchMock)).toBe(4); // nothing active: no more requests
  });

  it("does not poll at all when every run is finished", async () => {
    const fetchMock = serve(() => jsonResponse(listBody([makeRun({ run_number: 1 }), makeRun({ run_number: 2, status: "failed" })])));
    render(<RunsPage />);
    await flush();
    await advance(60_000);
    expect(listCalls(fetchMock)).toBe(1);
  });

  it("picks up a run that moves from queued to running without a reload", async () => {
    let current = [queuedRun(1)];
    serve(() => jsonResponse(listBody(current)));
    render(<RunsPage />);
    await flush();
    expect(badge().getByText("Queued")).toBeTruthy();
    current = [runningRun(1, { record_count: 5 })];
    await advance(POLL_MS);
    expect(badge().getByText("Running")).toBeTruthy();
    expect(badge().queryByText("Queued")).toBeNull();
  });

  it("pauses while the tab is hidden and refreshes immediately when it is visible again", async () => {
    const fetchMock = serve(() => jsonResponse(listBody([runningRun(1)])));
    render(<RunsPage />);
    await flush();
    expect(listCalls(fetchMock)).toBe(1);

    hidden = true;
    document.dispatchEvent(new Event("visibilitychange"));
    await advance(POLL_MS * 5);
    expect(listCalls(fetchMock)).toBe(1); // the pending poll found the tab hidden and stopped

    hidden = false;
    document.dispatchEvent(new Event("visibilitychange"));
    await flush();
    expect(listCalls(fetchMock)).toBe(2); // refreshed at once

    await advance(POLL_MS);
    expect(listCalls(fetchMock)).toBe(3); // and polling resumed
  });

  it("never starts a new poll while the previous request is still in flight", async () => {
    let calls = 0;
    const gate: { release?: (r: Response) => void } = {};
    const fetchMock = serve(() => {
      calls += 1;
      return calls === 1 ? jsonResponse(listBody([runningRun(1)])) : new Promise<Response>((r) => (gate.release = r));
    });
    render(<RunsPage />);
    await flush();
    await advance(POLL_MS); // second request starts and hangs
    expect(listCalls(fetchMock)).toBe(2);
    await advance(POLL_MS * 4);
    expect(listCalls(fetchMock)).toBe(2);
    gate.release?.(jsonResponse(listBody([runningRun(1)])));
    await advance(POLL_MS);
    expect(listCalls(fetchMock)).toBe(3);
  });

  it("slows down after a failed refresh and keeps showing the last list", async () => {
    let fail = false;
    const fetchMock = serve((_: Req) => (fail ? errorResponse(503, "busy") : jsonResponse(listBody([runningRun(1)]))));
    render(<RunsPage />);
    await flush();
    fail = true;
    await advance(POLL_MS);
    expect(listCalls(fetchMock)).toBe(2);
    await flush();
    expect(screen.getByRole("alert").textContent).toMatch(/out of date/);
    expect(screen.getByRole("table")).toBeTruthy();

    await advance(POLL_MS * 2);
    expect(listCalls(fetchMock)).toBe(2); // still waiting: the next try is later
    await advance(POLL_AFTER_ERROR_MS);
    expect(listCalls(fetchMock)).toBe(3);

    fail = false;
    await advance(POLL_AFTER_ERROR_MS);
    expect(screen.queryByRole("alert")).toBeNull(); // recovered
  });

  it("aborts the request that is in flight when the page is left, and stops polling", async () => {
    const signals: Array<AbortSignal | null | undefined> = [];
    const fetchMock = serve((req) => {
      signals.push(req.signal);
      return signals.length === 1 ? jsonResponse(listBody([runningRun(1)])) : new Promise<Response>(() => {});
    });
    const { unmount } = render(<RunsPage />);
    await flush();
    await advance(POLL_MS); // second request is now hanging
    expect(signals).toHaveLength(2);
    expect(signals[1]?.aborted).toBe(false);
    unmount();
    expect(signals[1]?.aborted).toBe(true);
    await advance(POLL_MS * 10);
    expect(listCalls(fetchMock)).toBe(2);
  });

  it("aborts the old list request when the filter changes", async () => {
    const signals: Array<AbortSignal | null | undefined> = [];
    const fetchMock = serve((req) => {
      signals.push(req.signal);
      return signals.length === 1 ? new Promise<Response>(() => {}) : jsonResponse(listBody([]));
    });
    render(<RunsPage />);
    await flush();
    expect(signals).toHaveLength(1);
    const select = screen.getByLabelText(/Status/) as HTMLSelectElement;
    await act(async () => {
      select.value = "failed";
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await flush();
    expect(signals[0]?.aborted).toBe(true);
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes("status=failed"))).toBe(true);
  });
});
