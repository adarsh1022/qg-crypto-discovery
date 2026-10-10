import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { REPORT_POLL_MS } from "../hooks/useResource";
import { backend } from "../test/fakeBackend";
import { errorResponse, installFetch, makeRun } from "../test/helpers";
import { makeSchedule, schedulesBackend } from "../test/scheduleHelpers";
import { RunsPage } from "./RunsPage";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const rowFor = (n: number) => within(screen.getByRole("row", { name: new RegExp(`^#${n}\\b`) }));

function serve(runs = [] as ReturnType<typeof makeRun>[], schedules = [] as ReturnType<typeof makeSchedule>[], hooks = {}) {
  const runsApi = backend(runs);
  const schedulesApi = schedulesBackend(schedules, hooks);
  const fetchMock = installFetch((req) => schedulesApi.handler(req) ?? runsApi.handler(req) ?? errorResponse(404, "not_found"));
  return { runsApi, schedulesApi, fetchMock };
}

describe("the Scheduled scans section on the Runs page", () => {
  it("is part of the page, above the runs, and keeps the runs list the only table", async () => {
    serve([makeRun({ run_number: 1 })]);
    render(<RunsPage />);
    expect(await screen.findByRole("heading", { name: "Scheduled scans" })).toBeTruthy();
    expect(await screen.findByRole("table")).toBeTruthy();                       // exactly one: getByRole would throw on two
    const order = screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent);
    expect(order.indexOf("Scheduled scans")).toBeLessThan(order.indexOf("Runs"));
  });

  it("says in the page text that scans can be scheduled, and that no relationship graph exists yet", async () => {
    serve();
    render(<RunsPage />);
    const intro = (await screen.findByRole("heading", { name: "Discovery runs" })).parentElement!.querySelector("p")!.textContent!;
    expect(intro).toMatch(/scheduled to\s+repeat on its own/);
    expect(intro).toMatch(/relationship graph is not implemented yet/);
  });

  it("lists a schedule and, next to it, the scheduled run it created, tied together by the same schedule id and trigger", async () => {
    const run = makeRun({ run_number: 3, trigger: "scheduled", schedule_id: "sched-0000000a", status: "running", finished_at: null, duration_ms: null, stop_reason: null });
    serve([run], [makeSchedule({ state: "skipping", last_run: { run_id: run.run_id, run_number: 3, status: "running", queued_at: run.queued_at, finished_at: null }, run_count: 1 })]);
    render(<RunsPage />);
    await screen.findByRole("table");
    const card = within(await screen.findByRole("listitem", { name: "Schedule sched-0000000a" }));
    expect(card.getByRole("link", { name: "#3" }).getAttribute("href")).toBe(`#/runs/${run.run_id}`);
    expect(rowFor(3).getByText("Scheduled")).toBeTruthy();
    expect(rowFor(3).getByText("sched-0000000a")).toBeTruthy();                  // the runs list names the schedule that made it
    expect(rowFor(3).getByText("Running")).toBeTruthy();
  });

  it("creates a schedule from the page", async () => {
    const { schedulesApi } = serve();
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByText(/No schedules yet/);
    await user.click(screen.getByText("New schedule"));
    await user.selectOptions(screen.getByLabelText("Kind of scan"), "tls");
    await user.type(screen.getByLabelText("Run every"), "30");
    await user.selectOptions(screen.getByLabelText("Interval unit"), "seconds");
    await user.type(screen.getByLabelText("Ports for this schedule"), "8443");
    await user.click(screen.getByRole("button", { name: "Create schedule" }));
    expect(await screen.findByRole("listitem", { name: /Schedule sched-/ })).toBeTruthy();
    expect(schedulesApi.created).toEqual([{ run_type: "tls", interval_seconds: 30, config: { ports: [8443] } }]);
  });

  it("does not disturb creating a one-off scan on the same page", async () => {
    const { fetchMock } = serve();
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByText(/No runs yet/);
    await user.type(screen.getByLabelText(/Folders to scan/), "C:\\certs");
    await user.click(screen.getByRole("button", { name: "Run filesystem scan" }));
    expect(await screen.findByText(/Run #1 is queued/)).toBeTruthy();
    const posts = fetchMock.mock.calls.filter(([, i]) => i?.method === "POST").map(([u]) => String(u));
    expect(posts).toEqual(["/api/runs"]);                                         // no schedule was created by a one-off scan
  });

  it("a failing schedule list does not break the runs list", async () => {
    serve([makeRun({ run_number: 1 })], [], { onList: () => errorResponse(503, "busy") });
    render(<RunsPage />);
    expect(await screen.findByRole("table")).toBeTruthy();
    expect(rowFor(1).getByText("Completed")).toBeTruthy();
    await waitFor(() => expect(screen.getByText(/Could not load the schedules/)).toBeTruthy());
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("the Type and Status filters still filter the runs, whatever the schedules panel shows", async () => {
    serve([makeRun({ run_number: 2, type: "tls", config: {} }), makeRun({ run_number: 1 })], [makeSchedule()]);
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByRole("table");
    await user.selectOptions(screen.getByLabelText(/Type/), "tls");
    await waitFor(() => expect(screen.queryByRole("row", { name: /^#1\b/ })).toBeNull());
    expect(rowFor(2).getByText("tls")).toBeTruthy();
    expect(screen.getByRole("listitem", { name: "Schedule sched-0000000a" })).toBeTruthy();   // unaffected by the runs filter
  });
});

describe("scheduled runs appear in the list by themselves", () => {
  const poll = (times = 1) => act(async () => { await vi.advanceTimersByTimeAsync(REPORT_POLL_MS * times); });
  const runsRequests = (mock: ReturnType<typeof installFetch>) => mock.mock.calls.filter(([u]) => String(u).startsWith("/api/runs")).length;

  it("lists a run the scheduler started without the user pressing Refresh", async () => {
    vi.useFakeTimers();
    const { runsApi, schedulesApi } = serve([], [makeSchedule({ run_count: 0 })]);
    render(<RunsPage />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.queryByRole("row", { name: /^#1\b/ })).toBeNull();
    const run = makeRun({ run_number: 1, trigger: "scheduled", schedule_id: "sched-0000000a" });
    runsApi.runs.push(run);                                                                 // the scheduler started a run ...
    schedulesApi.schedules[0] = { ...schedulesApi.schedules[0], run_count: 1, last_run: { run_id: run.run_id, run_number: 1, status: "completed", queued_at: run.queued_at, finished_at: run.finished_at } };
    await poll();                                                                           // ... the schedule list notices ...
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(rowFor(1).getByText("Scheduled")).toBeTruthy();                                  // ... and so does the runs list
  });

  it("does not start polling the runs list while nothing is happening", async () => {
    vi.useFakeTimers();
    const { fetchMock } = serve([makeRun({ run_number: 1 })], [makeSchedule({ run_count: 3 })]);
    render(<RunsPage />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    const before = runsRequests(fetchMock);
    await poll(5);
    expect(runsRequests(fetchMock)).toBe(before);                                           // schedules are polled; the runs list is not
  });
});
