import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { backend } from "../test/fakeBackend";
import { installFetch, makeRun, queuedRun, runningRun } from "../test/helpers";
import { RunsPage, createdNotice } from "./RunsPage";

afterEach(() => {
  vi.unstubAllGlobals();
});

const rowFor = (n: number) => screen.getByRole("row", { name: new RegExp(`^#${n}\\b`) });

async function showPage() {
  const user = userEvent.setup();
  render(<RunsPage />);
  return user;
}

describe("outcome wording (regression: the real backend gives failed runs stop_reason 'completed')", () => {
  it("shows why a failed or partial run ended, not the word 'completed'", async () => {
    installFetch(backend([
      makeRun({ run_number: 2, status: "failed", stop_reason: "completed", error_summary: "no_usable_data, roots_not_scanned:1, file_errors:1", record_count: 0, finding_count: 0, error_count: 1 }),
      makeRun({ run_number: 1, status: "partial", stop_reason: "completed", error_summary: "roots_not_scanned:1, file_errors:1", record_count: 3, finding_count: 3, error_count: 1 }),
    ]).handler);
    await showPage();
    await screen.findByRole("table");
    const failed = within(rowFor(2));
    expect(failed.getByText(/No usable results were produced\. 1 folder could not be scanned\./)).toBeTruthy();
    expect(failed.queryByText(/^completed$/i)).toBeNull();
    expect(failed.getByText("Failed")).toBeTruthy();
    expect(within(rowFor(1)).getByText(/1 folder could not be scanned\. 1 read error was recorded\./)).toBeTruthy();
    expect(within(rowFor(1)).getByText("Partial")).toBeTruthy();
  });

  it("words a TLS run's scan errors as scan errors, and a filesystem run's as read errors", async () => {
    installFetch(backend([
      makeRun({ run_number: 2, type: "tls", config: {}, status: "partial", stop_reason: "completed", error_summary: "file_errors:2, stopped_target_limit", record_count: 3, finding_count: 1, error_count: 2 }),
      makeRun({ run_number: 1, status: "partial", stop_reason: "completed", error_summary: "file_errors:2", record_count: 3, finding_count: 3, error_count: 2 }),
    ]).handler);
    await showPage();
    await screen.findByRole("table");
    expect(within(rowFor(2)).getByText(/2 scan errors were recorded\./)).toBeTruthy();
    expect(within(rowFor(2)).queryByText(/read error/)).toBeNull();
    expect(within(rowFor(1)).getByText(/2 read errors were recorded\./)).toBeTruthy();
  });

  it("tells a completed run with records from one that reported none, without claiming no files existed", async () => {
    installFetch(backend([
      makeRun({ run_number: 2, record_count: 0, finding_count: 0 }),
      makeRun({ run_number: 1, record_count: 1, finding_count: 1 }),
    ]).handler);
    await showPage();
    await screen.findByRole("table");
    expect(within(rowFor(2)).getByText("Completed, but the agent reported no records.")).toBeTruthy();
    expect(within(rowFor(1)).getByText("Finished normally.")).toBeTruthy();
    expect(screen.queryByText(/no certificate files/i)).toBeNull();
  });
});

describe("the notice about a newly created run follows that run", () => {
  async function createRunNamed(user: ReturnType<typeof userEvent.setup>) {
    await screen.findByText(/No runs yet/);
    await user.type(screen.getByLabelText(/Folders to scan/), "C:\\certs");
    await user.click(screen.getByRole("button", { name: "Run filesystem scan" }));
    await screen.findByText(/Run #1 is queued/);
  }

  it("moves from queued to running to completed as the list refreshes", async () => {
    const { handler, runs } = backend([]);
    installFetch(handler);
    const user = await showPage();
    await createRunNamed(user);

    runs[0] = runningRun(1);
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("Run #1 is running.")).toBeTruthy();
    expect(screen.queryByText(/is queued/)).toBeNull();

    runs[0] = makeRun({ run_number: 1 });
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("Run #1 completed.")).toBeTruthy();
    expect(screen.queryByText(/is running/)).toBeNull();
  });

  it("reports a completed run with no records as such", async () => {
    const { handler, runs } = backend([]);
    installFetch(handler);
    const user = await showPage();
    await createRunNamed(user);
    runs[0] = makeRun({ run_number: 1, record_count: 0, finding_count: 0 });
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("Run #1 completed, but the agent reported no records.")).toBeTruthy();
  });

  it("turns into a warning when the run fails", async () => {
    const { handler, runs } = backend([]);
    installFetch(handler);
    const user = await showPage();
    await createRunNamed(user);
    runs[0] = makeRun({ run_number: 1, status: "failed", error_summary: "no_usable_data" });
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    const notice = await screen.findByText("Run #1 failed.");
    expect(notice.className).toContain("notice-bad");
  });

  it("makes no claim about a run the current filter hides", async () => {
    installFetch(backend([]).handler);
    const user = await showPage();
    await createRunNamed(user);
    await user.selectOptions(screen.getByLabelText(/Status/), "failed");
    expect(await screen.findByText("Run #1 was created.")).toBeTruthy();
  });

  it("is derived from the run's real status", () => {
    expect(createdNotice(4, undefined)).toEqual({ text: "Run #4 was created.", bad: false });
    expect(createdNotice(4, queuedRun(4)).text).toMatch(/queued/);
    expect(createdNotice(4, makeRun({ run_number: 4, status: "partial" })).bad).toBe(true);
    expect(createdNotice(4, makeRun({ run_number: 4, status: "exploded" })).text).toBe("Run #4 was created.");
  });
});
