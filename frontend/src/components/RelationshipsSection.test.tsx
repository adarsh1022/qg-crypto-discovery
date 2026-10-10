import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { RelationshipPage } from "../api/relationshipTypes";
import { errorResponse, installFetch, jsonResponse, makeRun } from "../test/helpers";
import { makePresented, makeStoredOn, recorded } from "../test/relationshipFixtures";
import { makeRelationships, sha } from "../test/reportBackend";
import { RelationshipsSection, recordingMessage } from "./RelationshipsSection";

afterEach(() => {
  vi.unstubAllGlobals();
});

const RID = "a".repeat(32);   // run ids are 32 hex characters
const fsRun = makeRun({ run_number: 4 });
const tlsRun = makeRun({ run_number: 5, type: "tls", config: {} });

function show(page: RelationshipPage | (() => Response), version = "v1") {
  const fetchMock = installFetch((req) =>
    /\/relationships$/.test(req.path) ? (typeof page === "function" ? page() : jsonResponse(page)) : errorResponse(404, "not_found"));
  const view = render(<RelationshipsSection runId={RID} key={version} version={version} />);
  return { fetchMock, view };
}

describe("the recording states say different things", () => {
  const base = (state: RelationshipPage["recording"]["state"], over = {}) => ({
    ...makeRelationships(fsRun), recording: { state, expected: 0, recorded: 0, missing: 0, unexpected: 0, ...over },
  });

  it("'Not recorded for this run' (an older run) is not the same as 'No relationships expected'", () => {
    const older = recordingMessage(base("incomplete", { expected: 3, missing: 3 }));
    const none = recordingMessage(base("none_expected"));
    expect(older.headline).toBe("Not recorded for this run.");
    expect(older.detail).toMatch(/supports 3 relationships, but none was stored/);
    expect(older.detail).toMatch(/before relationship recording existed/);
    expect(older.detail).toMatch(/Nothing has been inferred/);
    expect(none.headline).toBe("No relationships expected.");
    expect(none.detail).not.toMatch(/not recorded|before relationship recording/i);
    expect(older.headline).not.toBe(none.headline);
  });

  it("a partly recorded run says so, with the numbers", () => {
    const partly = recordingMessage(base("incomplete", { expected: 4, recorded: 2, missing: 2, unexpected: 1 }));
    expect(partly.headline).toBe("Only partly recorded for this run.");
    expect(partly.detail).toMatch(/2 of 4 relationships .* are missing or differ, and 1 stored is not supported by it/);
  });

  it("pending says it is not recorded yet, and a run that did not complete cleanly warns that absence proves nothing", () => {
    expect(recordingMessage(base("pending")).headline).toBe("Not recorded yet.");
    const failed = { ...base("none_expected"), run: { ...fsRun_run(), status: "failed" } };
    expect(recordingMessage(failed).detail).toMatch(/did not complete cleanly, so the absence of a relationship does not mean there is none/);
  });
});

function fsRun_run() {
  return makeRelationships(fsRun).run;
}

describe("a filesystem run", () => {
  it("lists certificate -> host rows as parsed-from-a-file, never as use", async () => {
    show(recorded(fsRun, [makeStoredOn(1), makeStoredOn(2)]));
    expect(await screen.findByRole("heading", { name: "Relationships" })).toBeTruthy();
    expect(await screen.findByText(/2 relationships recorded for this run/)).toBeTruthy();
    const table = screen.getByRole("table", { name: /Relationships recorded for run #4/ });
    expect(within(table).getAllByRole("row")).toHaveLength(3);                        // header + 2
    const row = within(screen.getByRole("row", { name: /host1\.example/ }));
    expect(row.getByText("Certificate parsed from a file on this host")).toBeTruthy();
    expect(row.getByText("WORKSTATION")).toBeTruthy();
    expect(row.getByText("agent-1")).toBeTruthy();
    expect(row.getByText("2 observations")).toBeTruthy();
    expect(row.getByText(/5 in 3 runs/)).toBeTruthy();
    expect(document.body.textContent).toMatch(/shows the file exists there, not that the certificate is in use/);
    expect(screen.queryByRole("columnheader", { name: /Listening process/ })).toBeNull();     // TLS-only columns are absent
  });

  it("shows the older-run message and no table when nothing was recorded", async () => {
    show({ ...makeRelationships(fsRun), recording: { state: "incomplete", expected: 3, recorded: 0, missing: 3, unexpected: 0 } });
    expect(await screen.findByText("Not recorded for this run.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("shows 'No relationships expected' and no table for a run with nothing to relate", async () => {
    show(makeRelationships(fsRun));
    expect(await screen.findByText("No relationships expected.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByText("Not recorded for this run.")).toBeNull();
  });

  it("says when the list is cut short", async () => {
    show(recorded(fsRun, [makeStoredOn(1)], { total: 9, truncated: true }));
    expect(await screen.findByText("Showing the first 1 of 9 relationships.")).toBeTruthy();
  });
});

describe("a TLS run", () => {
  it("presents the listener as a probed local listener, never as communication", async () => {
    show(recorded(tlsRun, [makePresented(1)]));
    const row = within(await screen.findByRole("row", { name: /127\.0\.0\.1:8001\/tcp/ }));
    expect(row.getByText("Certificate presented by a local listener (active probe)")).toBeTruthy();
    expect(row.getByText("Local listener")).toBeTruthy();
    expect(row.getByText(/on host WORKSTATION/)).toBeTruthy();
    expect(row.getByText("svc.exe")).toBeTruthy();
    expect(row.getByText("C:\\svc\\svc.exe")).toBeTruthy();
    expect(document.body.textContent).toMatch(/active probe, not observed traffic: there is no remote peer, direction or packet count/);
    expect(document.body.textContent).not.toMatch(/communicat|connected to|traffic between/i);
    expect(document.body.textContent).not.toMatch(/\bPID\b/);
  });

  it("says 'Not determined' when the process was ambiguous or unattributed", async () => {
    show(recorded(tlsRun, [makePresented(1, { process: null })]));
    expect(await screen.findByText("Not determined")).toBeTruthy();
  });

  it("shows filesystem evidence as separate, with host, run context and a link, and never as proof of use", async () => {
    const run = makeRun({ run_number: 2 });
    const page = recorded(tlsRun, [makePresented(1, { filesystem_evidence: { hosts: [
      { host_id: "agent-1", hostname: "WORKSTATION", observations: 3, runs: 2, last_seen_at: "2026-10-10T07:00:00Z", latest_run_id: run.run_id, latest_run_number: 2 },
    ], omitted: 1 } })]);
    show(page);
    expect(await screen.findByRole("columnheader", { name: /Same certificate in files \(separate evidence\)/ })).toBeTruthy();
    const cell = screen.getByText(/File with the same fingerprint on WORKSTATION/);
    expect(cell.textContent).toMatch(/3 sightings in 2 runs/);
    expect(within(cell).getByRole("link", { name: "run #2" }).getAttribute("href")).toBe(`#/runs/${run.run_id}`);
    expect(screen.getByText("and 1 more host not shown.")).toBeTruthy();
  });

  it("says when no filesystem scan holds the certificate", async () => {
    show(recorded(tlsRun, [makePresented(1)]));
    expect(await screen.findByText("Not found in any filesystem scan.")).toBeTruthy();
  });
});

describe("loading, failure and refresh", () => {
  it("shows a loading status first", async () => {
    show(makeRelationships(fsRun));
    expect(screen.getByText(/Loading relationships/)).toBeTruthy();
    await screen.findByText("No relationships expected.");
  });

  it("a failure is quiet (no alert), explains itself, and can be retried", async () => {
    let up = false;
    const { fetchMock } = show(() => (up ? jsonResponse(makeRelationships(fsRun)) : errorResponse(503, "busy")));
    const user = userEvent.setup();
    expect(await screen.findByText(/Could not load the relationships/)).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    up = true;
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("No relationships expected.")).toBeTruthy();
    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it("a malformed answer is an error, not an empty table", async () => {
    show(() => jsonResponse({ run: {}, items: "nope" }));
    expect(await screen.findByText(/Could not load the relationships/)).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("looks again when the run progressed, keeping what is shown meanwhile", async () => {
    let page: RelationshipPage = makeRelationships({ ...fsRun, status: "running" });
    const fetchMock = installFetch((req) => (/\/relationships$/.test(req.path) ? jsonResponse(page) : errorResponse(404, "not_found")));
    const { rerender } = render(<RelationshipsSection runId={RID} version="running" />);
    expect(await screen.findByText("Not recorded yet.")).toBeTruthy();
    page = recorded(fsRun, [makeStoredOn(1)]);
    rerender(<RelationshipsSection runId={RID} version="completed" />);
    expect(await screen.findByText(/1 relationship recorded for this run/)).toBeTruthy();
    await waitFor(() => expect(fetchMock.mock.calls.length).toBe(2));
  });

  it("requests only this run's relationships", async () => {
    const { fetchMock } = show(makeRelationships(fsRun));
    await screen.findByText("No relationships expected.");
    expect(fetchMock.mock.calls.map(([u]) => String(u))).toEqual([`/api/runs/${RID}/relationships`]);
    expect(sha(1)).toHaveLength(64);
  });
});
