import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { REPORT_POLL_MS } from "../hooks/useResource";
import { errorResponse, installFetch, jsonResponse } from "../test/helpers";
import { makeSchedule, schedulesBackend } from "../test/scheduleHelpers";
import { SchedulesPanel } from "./SchedulesPanel";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const LAST = { run_id: "b".repeat(32), run_number: 7, status: "running", queued_at: "2026-03-01T12:05:00.000Z", finished_at: null };
const item = (id: string) => within(screen.getByRole("listitem", { name: `Schedule ${id}` }));

function setup(initial = [makeSchedule()], hooks = {}) {
  const fake = schedulesBackend(initial, hooks);
  const fetchMock = installFetch((req) => fake.handler(req) ?? errorResponse(404, "not_found"));
  const user = userEvent.setup();
  const view = render(<SchedulesPanel />);
  return { ...fake, fetchMock, user, ...view };
}

describe("loading, empty and error states", () => {
  it("says it is loading, then that there are no schedules", async () => {
    setup([]);
    expect(screen.getByText(/Loading schedules/)).toBeTruthy();
    expect(await screen.findByText(/No schedules yet/)).toBeTruthy();
    expect(screen.queryByRole("list", { name: "Scheduled scans" })).toBeNull();
  });

  it("explains a failed load without shouting, and its Retry works", async () => {
    let fail = true;
    const { user } = setup([makeSchedule()], { onList: () => (fail ? errorResponse(503, "busy") : undefined) });
    expect(await screen.findByText(/Could not load the schedules/)).toBeTruthy();
    expect(screen.getByText(/busy/i)).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    fail = false;
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("listitem", { name: "Schedule sched-0000000a" })).toBeTruthy();
    expect(screen.queryByText(/Could not load the schedules/)).toBeNull();
  });

  it("an unusable answer is reported as such", async () => {
    installFetch(() => jsonResponse({ schedules: "nope" }));
    render(<SchedulesPanel />);
    expect(await screen.findByText(/response this page does not understand/)).toBeTruthy();
  });

  it("keeps showing the last good list, marked out of date, when a refresh fails", async () => {
    vi.useFakeTimers();
    let fail = false;
    const fake = schedulesBackend([makeSchedule()], { onList: () => (fail ? errorResponse(503, "busy") : undefined) });
    installFetch((req) => fake.handler(req) ?? errorResponse(404, "not_found"));
    render(<SchedulesPanel />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getByRole("listitem", { name: "Schedule sched-0000000a" })).toBeTruthy();
    fail = true;
    await act(async () => { await vi.advanceTimersByTimeAsync(REPORT_POLL_MS); });
    expect(screen.getByText(/may be out of date/)).toBeTruthy();
    expect(screen.getByRole("listitem", { name: "Schedule sched-0000000a" })).toBeTruthy();
  });
});

describe("what it shows is what the backend returned", () => {
  it("shows type, scope, interval, state, next run, last run with its real status, run count and the schedule id", async () => {
    setup([makeSchedule({ interval_seconds: 90, state: "skipping", next_due_at: "2026-03-01T12:07:00.000Z", last_run: LAST, run_count: 7 })]);
    const s = within(await screen.findByRole("listitem", { name: "Schedule sched-0000000a" }));
    expect(s.getByText("Filesystem scan")).toBeTruthy();
    expect(s.getByText("C:\\certs")).toBeTruthy();
    expect(s.getByText("every 1 min 30 s")).toBeTruthy();
    expect(s.getByText("sched-0000000a")).toBeTruthy();
    expect(s.getByText("Skipping")).toBeTruthy();
    expect(s.getByText(/a run that falls due now is skipped/)).toBeTruthy();
    expect(s.getByText("Running")).toBeTruthy();                                   // the run's own lifecycle status
    expect(s.queryByText("Completed")).toBeNull();
    expect(s.getByRole("link", { name: "#7" }).getAttribute("href")).toBe(`#/runs/${LAST.run_id}`);
    expect(s.getByText("7")).toBeTruthy();                                          // runs so far
    expect(s.getByText(/2026/)).toBeTruthy();                                       // the next run time
  });

  it("shows each of the three states as what it is", async () => {
    setup([
      makeSchedule({ schedule_id: "sched-00000001", state: "waiting" }),
      makeSchedule({ schedule_id: "sched-00000002", state: "skipping" }),
      makeSchedule({ schedule_id: "sched-00000003", state: "paused", enabled: false, next_due_at: null }),
    ]);
    await screen.findByRole("listitem", { name: "Schedule sched-00000001" });
    expect(item("sched-00000001").getByText("Waiting")).toBeTruthy();
    expect(item("sched-00000001").getByText(/Nothing else is running/)).toBeTruthy();
    expect(item("sched-00000002").getByText("Skipping")).toBeTruthy();
    expect(item("sched-00000003").getByText("Paused")).toBeTruthy();
    expect(item("sched-00000003").getByText(/No runs are created until it is resumed/)).toBeTruthy();
    expect(item("sched-00000003").queryByText(/2026/)).toBeNull();                 // a paused schedule has no next run
  });

  it("never shows a next run for a paused schedule, even if the data still carried a due time", async () => {
    setup([makeSchedule({ state: "paused", enabled: false, next_due_at: "2026-03-01T12:05:00.000Z" })]);
    const s = within(await screen.findByRole("listitem", { name: "Schedule sched-0000000a" }));
    expect(s.getByText("Paused")).toBeTruthy();
    expect(s.queryByText(/2026/)).toBeNull();
  });

  it("calls a state it does not know Unknown and says nothing else about it", async () => {
    setup([makeSchedule({ state: "<b>exploding</b>" })]);
    const s = within(await screen.findByRole("listitem", { name: "Schedule sched-0000000a" }));
    expect(s.getByText("Unknown")).toBeTruthy();
    expect(s.queryByText(/exploding/)).toBeNull();
    expect(s.queryByText("Waiting")).toBeNull();
  });

  it("a schedule that has not run yet says so instead of inventing a run", async () => {
    setup([makeSchedule({ last_run: null, run_count: 0 })]);
    const s = within(await screen.findByRole("listitem", { name: "Schedule sched-0000000a" }));
    expect(s.getByText("None yet")).toBeTruthy();
    expect(s.queryByRole("link")).toBeNull();
  });

  it("shows a TLS schedule's ports, or the broad-probe warning when it has none", async () => {
    setup([
      makeSchedule({ schedule_id: "sched-00000001", run_type: "tls", config: { ports: [8443, 9443] } }),
      makeSchedule({ schedule_id: "sched-00000002", run_type: "tls", config: {}, probe_all_listeners: true }),
    ]);
    await screen.findByRole("listitem", { name: "Schedule sched-00000001" });
    expect(item("sched-00000001").getByText("TLS metadata scan")).toBeTruthy();
    expect(item("sched-00000001").getByText("TLS listeners on this machine (ports 8443, 9443)")).toBeTruthy();
    expect(item("sched-00000001").queryByText(/Probes every eligible TLS listener/)).toBeNull();
    expect(item("sched-00000002").getByText(/Probes every eligible TLS listener on this machine each time/)).toBeTruthy();
  });

  it("renders hostile text as text, never as markup", async () => {
    setup([makeSchedule({ config: { roots: ["<img src=x onerror=alert(1)>"] } })]);
    const s = within(await screen.findByRole("listitem", { name: "Schedule sched-0000000a" }));
    expect(s.getByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });
});

describe("pause and resume", () => {
  it("pauses with exactly {enabled:false} and then shows the schedule as paused", async () => {
    const { user, patched } = setup();
    await user.click(await screen.findByRole("button", { name: "Pause schedule sched-0000000a" }));
    await waitFor(() => expect(item("sched-0000000a").getByText("Paused")).toBeTruthy());
    expect(patched).toEqual([{ id: "sched-0000000a", enabled: false }]);
    expect(screen.getByRole("button", { name: "Resume schedule sched-0000000a" })).toBeTruthy();
    expect(item("sched-0000000a").queryByText(/2026/)).toBeNull();
  });

  it("resumes with {enabled:true} and shows the new next run", async () => {
    const { user, patched } = setup([makeSchedule({ enabled: false, state: "paused", next_due_at: null })]);
    await user.click(await screen.findByRole("button", { name: "Resume schedule sched-0000000a" }));
    await waitFor(() => expect(item("sched-0000000a").getByText("Waiting")).toBeTruthy());
    expect(patched).toEqual([{ id: "sched-0000000a", enabled: true }]);
    expect(item("sched-0000000a").getByText(/2026/)).toBeTruthy();
  });

  it("cannot be clicked twice while the request is in flight", async () => {
    let release: (r: Response) => void = () => {};
    const fake = schedulesBackend([makeSchedule()]);
    installFetch((req) => (req.method === "PATCH" ? new Promise<Response>((r) => (release = r)) : (fake.handler(req) ?? errorResponse(404, "not_found"))));
    const user = userEvent.setup();
    render(<SchedulesPanel />);
    const button = await screen.findByRole("button", { name: "Pause schedule sched-0000000a" });
    await user.click(button);
    const busy = await screen.findByRole("button", { name: "Pause schedule sched-0000000a" });
    expect((busy as HTMLButtonElement).disabled).toBe(true);
    expect(busy.textContent).toBe("Pausing…");
    await user.click(busy);
    expect(fake.patched).toHaveLength(0);
    release(jsonResponse({ schedule: makeSchedule({ enabled: false, state: "paused", next_due_at: null }) }));
    await waitFor(() => expect((screen.getByRole("button", { name: /schedule sched-0000000a/ }) as HTMLButtonElement).disabled).toBe(false));
  });

  it("shows why it failed, keeps the real state and lets the user try again", async () => {
    const { user } = setup([makeSchedule()], { onPatch: () => errorResponse(404, "schedule_not_found", "No such schedule.") });
    await user.click(await screen.findByRole("button", { name: "Pause schedule sched-0000000a" }));
    expect((await screen.findByRole("alert")).textContent).toBe("That schedule no longer exists.");
    expect(item("sched-0000000a").getByText("Waiting")).toBeTruthy();                       // not claimed to be paused
    expect((screen.getByRole("button", { name: "Pause schedule sched-0000000a" }) as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("polling", () => {
  it("looks again every few seconds so a run that finishes is shown as it finished, and not before", async () => {
    vi.useFakeTimers();
    const fake = schedulesBackend([makeSchedule({ last_run: LAST, run_count: 1, state: "skipping" })]);
    installFetch((req) => fake.handler(req) ?? errorResponse(404, "not_found"));
    render(<SchedulesPanel />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(item("sched-0000000a").getByText("Running")).toBeTruthy();
    fake.schedules[0] = { ...fake.schedules[0], state: "waiting", last_run: { ...LAST, status: "completed", finished_at: "2026-03-01T12:06:00.000Z" } };
    await act(async () => { await vi.advanceTimersByTimeAsync(REPORT_POLL_MS); });
    expect(item("sched-0000000a").getByText("Completed")).toBeTruthy();
    expect(item("sched-0000000a").getByText("Waiting")).toBeTruthy();
  });

  it("stops looking when the page is not in use", async () => {
    vi.useFakeTimers();
    const fake = schedulesBackend([makeSchedule()]);
    const fetchMock = installFetch((req) => fake.handler(req) ?? errorResponse(404, "not_found"));
    render(<SchedulesPanel active={false} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    const first = fetchMock.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(REPORT_POLL_MS * 5); });
    expect(fetchMock.mock.calls.length).toBe(first);
  });
});
