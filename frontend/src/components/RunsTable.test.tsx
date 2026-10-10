import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { makeRun, queuedRun, runningRun } from "../test/helpers";
import { RunsTable } from "./RunsTable";

const draw = (runs = [] as ReturnType<typeof makeRun>[]) =>
  render(<RunsTable runs={runs} nowMs={Date.parse("2026-03-01T12:00:30.000Z")} actions={{}} onCancel={vi.fn()} />);
const rowFor = (n: number) => within(screen.getByRole("row", { name: new RegExp(`^#${n}\\b`) }));

describe("trigger and identity", () => {
  it("has a Trigger column", () => {
    draw([makeRun({ run_number: 1 })]);
    expect(screen.getByRole("columnheader", { name: "Trigger" })).toBeTruthy();
  });

  it("shows the trigger exactly as the backend recorded it: Manual for a manual run", () => {
    draw([makeRun({ run_number: 1, trigger: "manual", schedule_id: null })]);
    expect(rowFor(1).getByText("Manual")).toBeTruthy();
    expect(rowFor(1).queryByText(/Scheduled/)).toBeNull();
  });

  it("shows Scheduled with its schedule id only when the backend says so (a value from the data, not invented)", () => {
    draw([makeRun({ run_number: 2, trigger: "scheduled", schedule_id: "nightly-1" })]);
    expect(rowFor(2).getByText("Scheduled")).toBeTruthy();
    expect(rowFor(2).getByText("nightly-1")).toBeTruthy();
  });

  it("does not show a schedule id on a manual run, even if one were present in the data", () => {
    draw([makeRun({ run_number: 3, trigger: "manual", schedule_id: "stray" })]);
    expect(rowFor(3).queryByText("stray")).toBeNull();
  });

  it("shows a trigger it does not know as plain text, never as Manual or Scheduled", () => {
    draw([makeRun({ run_number: 4, trigger: "<b>odd</b>" })]);
    expect(rowFor(4).getByText("<b>odd</b>")).toBeTruthy();
    expect(rowFor(4).queryByText("Manual")).toBeNull();
    expect(rowFor(4).queryByText("Scheduled")).toBeNull();
  });

  it("shows the first 8 characters of the run id, with the whole id as a tooltip, next to the run number and type", () => {
    const run = makeRun({ run_number: 5, type: "tls", config: {} });
    draw([run]);
    const code = rowFor(5).getByText(run.run_id.slice(0, 8));
    expect(code.getAttribute("title")).toBe(run.run_id);
    expect(run.run_id).toHaveLength(32);
    expect(rowFor(5).getByText("tls")).toBeTruthy();
  });
});

describe("opening a run's report", () => {
  it("links the run number to the report once the run has started, for both run types", () => {
    const fs = makeRun({ run_number: 1 });
    const tls = makeRun({ run_number: 2, type: "tls", config: {} });
    draw([tls, fs]);
    expect(rowFor(1).getByRole("link", { name: "#1" }).getAttribute("href")).toBe(`#/runs/${fs.run_id}`);
    expect(rowFor(2).getByRole("link", { name: "#2" }).getAttribute("href")).toBe(`#/runs/${tls.run_id}`);
  });

  it("links a running run too (results so far), but not a queued one", () => {
    draw([queuedRun(3), runningRun(4)]);
    expect(rowFor(4).getByRole("link", { name: "#4" })).toBeTruthy();
    expect(rowFor(3).queryByRole("link")).toBeNull();
  });

  it("keeps the existing Report buttons with their own names", () => {
    draw([makeRun({ run_number: 1 }), makeRun({ run_number: 2, type: "tls", config: {} })]);
    expect(rowFor(1).getByRole("link", { name: "Open report for run 1" })).toBeTruthy();
    expect(rowFor(2).getByRole("link", { name: "Open TLS report for run 2" })).toBeTruthy();
  });

  it("does not link a run of a type the report page does not know", () => {
    draw([makeRun({ run_number: 6, type: "mystery" })]);
    expect(rowFor(6).queryByRole("link")).toBeNull();
  });
});

describe("what the findings column calls its number (unchanged from the last pass)", () => {
  it("keeps 'Sightings' and its filesystem tooltip, and labels TLS rows as completed handshakes", () => {
    draw([makeRun({ run_number: 1, finding_count: 6 }), makeRun({ run_number: 2, type: "tls", config: {}, finding_count: 2 })]);
    expect(screen.getByRole("columnheader", { name: "Sightings" }).getAttribute("title")).toMatch(/counts once per file/);
    expect(rowFor(2).getByText("completed handshakes")).toBeTruthy();
    expect(rowFor(1).queryByText(/handshake/)).toBeNull();
  });
});
