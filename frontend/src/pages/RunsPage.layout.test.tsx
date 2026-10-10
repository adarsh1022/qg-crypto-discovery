import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { formatTime } from "../format";
import { backend } from "../test/fakeBackend";
import { installFetch, makeRun } from "../test/helpers";
import { RunsPage } from "./RunsPage";

afterEach(() => {
  vi.unstubAllGlobals();
});

const form = () => screen.getByText("New scan").closest("details") as HTMLDetailsElement;

describe("the scan form does not dominate the page", () => {
  it("is open for a first-time user with no runs", async () => {
    installFetch(backend([]).handler);
    render(<RunsPage />);
    await screen.findByText(/No runs yet/);
    expect(form().open).toBe(true);
  });

  it("is tucked away once there are runs, so the list is what you see, and can be opened again", async () => {
    installFetch(backend([makeRun({ run_number: 1 })]).handler);
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByRole("table");
    await waitFor(() => expect(form().open).toBe(false));
    await user.click(screen.getByText("New scan"));
    await waitFor(() => expect(form().open).toBe(true));
    expect(screen.getByLabelText(/Folders to scan/)).toBeTruthy();
  });

  it("does not close again by itself after the user opened it", async () => {
    const { handler, runs } = backend([makeRun({ run_number: 1 })]);
    installFetch(handler);
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByRole("table");
    await waitFor(() => expect(form().open).toBe(false));
    await user.click(screen.getByText("New scan"));
    await waitFor(() => expect(form().open).toBe(true));
    runs.unshift(makeRun({ run_number: 2 }));
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByRole("row", { name: /^#2/ });
    expect(form().open).toBe(true);
  });

  it("closes after a scan is created, so the new run is visible", async () => {
    installFetch(backend([]).handler);
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByText(/No runs yet/);
    await user.type(screen.getByLabelText(/Folders to scan/), "C:\\certs");
    await user.click(screen.getByRole("button", { name: "Run filesystem scan" }));
    const row = await screen.findByRole("row", { name: /^#1/ });
    expect(within(row).getByText("Queued")).toBeTruthy();
    await waitFor(() => expect(form().open).toBe(false));
  });
});

describe("formatTime", () => {
  it("spells the month out so day and month cannot be confused", () => {
    const text = formatTime("2026-10-11T08:05:00.000Z");
    expect(text).toMatch(/2026/);
    expect(text).toMatch(/[A-Za-z]{3}/);
    expect(text).not.toMatch(/^\d{1,2}\/\d{1,2}\/\d{2,4}/); // not 10/11/2026
  });
});
