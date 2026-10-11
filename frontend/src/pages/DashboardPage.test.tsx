import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { dashboardBackend, makeDashboard, makeDashboardSummary, makeStats, type DashboardWorld } from "../test/dashboardFixtures";
import { errorResponse, installFetch, makeRun } from "../test/helpers";
import { makeTlsSummary } from "../test/tlsFixtures";
import { DashboardPage } from "./DashboardPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const fsRun = makeRun({ run_number: 6, record_count: 9, finding_count: 8 });
const tlsOld = makeRun({ run_number: 7, type: "tls", config: {} });
const tlsNew = makeRun({ run_number: 9, type: "tls", config: {} });

const stats = makeStats([
  { type: "filesystem", status: "completed", count: 3 }, { type: "tls", status: "completed", count: 2 },
  { type: "filesystem", status: "failed", count: 1 }, { type: "tls", status: "partial", count: 1 }, { type: "tls", status: "running", count: 1 },
]);

function world(over: Partial<DashboardWorld> = {}): DashboardWorld {
  return {
    stats,
    dashboard: makeDashboard(fsRun),
    tlsRuns: [tlsNew, tlsOld],
    tlsSummaries: {
      [tlsNew.run_id]: makeTlsSummary(tlsNew, {
        tls_versions: { SSL3: 0, "TLS1.0": 0, "TLS1.1": 0, "TLS1.2": 1, "TLS1.3": 3 },
        cipher_suites: { top: [{ cipher_suite: "TLS_AES_256_GCM_SHA384", handshakes: 3 }, { cipher_suite: "ECDHE-RSA-AES256-GCM-SHA384", handshakes: 1 }], other: { groups: 2, handshakes: 1 }, total_groups: 4, limit: 2 },
      }, { handshakes_completed: 4, probe_attempts: 6 }),
    },
    ...over,
  };
}

function show(w: DashboardWorld) {
  const be = dashboardBackend(w);
  const fetchMock = installFetch((req) => be.handler(req) ?? errorResponse(404, "not_found"));
  const user = userEvent.setup();
  render(<DashboardPage />);
  return { fetchMock, user, be };
}
const urls = (m: ReturnType<typeof installFetch>) => m.mock.calls.map(([u]) => String(u));
const chart = (name: string) => within(screen.getByRole("figure", { name }));
const row = (name: string, label: string) => within(chart(name).getByRole("list", { name: new RegExp(`^${name}`) })).getByText(label).closest("li") as HTMLElement;

describe("what the dashboard asks the backend for", () => {
  it("uses only the existing endpoints: run statistics, the dashboard, the TLS run list, and one TLS summary", async () => {
    const { fetchMock } = show(world());
    await screen.findByRole("figure", { name: "TLS versions" });
    expect(urls(fetchMock).sort()).toEqual([
      "/api/dashboard", "/api/runs/stats", "/api/runs?type=tls&limit=100", `/api/runs/${tlsNew.run_id}/tls/summary`,
    ].sort());
  });

  it("charts the newest TLS run that finished with results, skipping running, queued and failed ones", async () => {
    const running = makeRun({ run_number: 12, type: "tls", status: "running", config: {}, finished_at: null });
    const failed = makeRun({ run_number: 11, type: "tls", status: "failed", config: {} });
    const partial = makeRun({ run_number: 10, type: "tls", status: "partial", config: {} });
    const { fetchMock } = show(world({ tlsRuns: [running, failed, partial, tlsOld], tlsSummaries: {} }));
    await screen.findByText(/Latest finished TLS run #10 \(partial\)/);
    expect(urls(fetchMock).filter((u) => u.includes("/tls/summary"))).toEqual([`/api/runs/${partial.run_id}/tls/summary`]);
    expect(screen.getByText(/did not complete cleanly, so an empty chart does not mean there are no TLS services/)).toBeTruthy();
  });
});

describe("the charts show the backend's numbers", () => {
  it("runs by status and type: each status row is a total with its filesystem/TLS breakdown", async () => {
    show(world());
    await screen.findByRole("figure", { name: "Runs by status and type" });
    expect(screen.getByText("All 8 runs recorded, whatever their age.")).toBeTruthy();
    expect(row("Runs by status and type", "Completed").textContent).toContain("5 (Filesystem 3, TLS 2)");
    expect(row("Runs by status and type", "Failed").textContent).toContain("1 (Filesystem 1)");
    expect(row("Runs by status and type", "Partial").textContent).toContain("1 (TLS 1)");
    expect(row("Runs by status and type", "Queued").textContent).toMatch(/Queued0$/);
    expect(within(chart("Runs by status and type").getByRole("list", { name: "Legend" })).getAllByRole("listitem")).toHaveLength(2);
  });

  it("certificate validity, key algorithms and signature algorithms come from the latest finished filesystem run, and say which", async () => {
    show(world());
    await screen.findByRole("figure", { name: "Certificate validity" });
    expect(screen.getByText(/Latest finished filesystem run #6 \(completed\), 8 unique certificates\./)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open run #6's report" }).getAttribute("href")).toBe(`#/runs/${fsRun.run_id}`);
    expect(screen.getByRole("link", { name: "Open run #9's report" }).getAttribute("href")).toBe(`#/runs/${tlsNew.run_id}`);
    expect(row("Certificate validity", "Valid").textContent).toMatch(/Valid5$/);
    expect(row("Certificate validity", "Expiring within 30 days").textContent).toMatch(/2$/);
    expect(row("Certificate validity", "Expired").textContent).toMatch(/1$/);
    expect(row("Key algorithms", "RSA 2048").textContent).toContain("4 (6 sightings)");
    expect(row("Key algorithms", "EC P-256").textContent).toMatch(/2$/);
    expect(row("Key algorithms", "Other (2 more)").textContent).toMatch(/2$/);
    expect(row("Signature algorithms", "sha256WithRSAEncryption").textContent).toContain("6 (7 sightings)");
    expect(screen.getByText(/These charts describe that one run, not every run\./)).toBeTruthy();
    expect(screen.getByText(/Unique certificates, judged as of /)).toBeTruthy();                 // the time the backend reports, not "today"
  });

  it("TLS versions and cipher suites count completed handshakes of the latest finished TLS run, and say they are probes", async () => {
    show(world());
    await screen.findByRole("figure", { name: "TLS versions" });
    expect(screen.getByText(/Latest finished TLS run #9 \(completed\): 4 completed handshakes/)).toBeTruthy();
    expect(screen.getByText(/active probe results, not observed traffic, and only completed handshakes are counted/)).toBeTruthy();
    expect(row("TLS versions", "TLS1.3").textContent).toMatch(/3$/);
    expect(row("TLS versions", "TLS1.2").textContent).toMatch(/1$/);
    expect(within(chart("TLS versions").getByRole("list", { name: /^TLS versions/ })).queryByText("SSL3")).toBeNull();      // never negotiated: not drawn
    expect(row("Cipher suites", "TLS_AES_256_GCM_SHA384").textContent).toMatch(/3$/);
    expect(row("Cipher suites", "Other (2 more)").textContent).toMatch(/1$/);
  });

  it("the key figures repeat the same numbers, each with the run it comes from", async () => {
    show(world());
    await screen.findByRole("figure", { name: "TLS versions" });
    const figures = within(screen.getByRole("region", { name: "Key figures" }));
    expect(figures.getByText("Runs recorded").parentElement!.textContent).toContain("8");
    expect(figures.getByText("Runs finished").parentElement!.textContent).toContain("7");
    expect(figures.getByText("Unique certificates").parentElement!.textContent).toContain("8latest filesystem run #6");
    expect(figures.getByText("Expiring or expired").parentElement!.textContent).toContain("3");
    expect(figures.getByText("TLS handshakes completed").parentElement!.textContent).toContain("4latest TLS run #9");
  });
});

describe("when there is nothing to chart", () => {
  it("an empty database says so in every section and invents nothing", async () => {
    show({ stats: makeStats([]), dashboard: makeDashboard(null), tlsRuns: [] });
    expect(await screen.findByText("No run has been recorded yet.")).toBeTruthy();
    expect(await screen.findByText(/No filesystem scan has finished yet, so there are no certificate figures/)).toBeTruthy();
    expect(await screen.findByText(/No TLS scan has finished with results yet/)).toBeTruthy();
    expect(screen.queryByRole("figure", { name: "Certificate validity" })).toBeNull();
    expect(screen.queryByRole("listitem")).toBeNull();
    const figures = within(screen.getByRole("region", { name: "Key figures" }));
    expect(figures.getByText("Runs recorded").parentElement!.textContent).toContain("0");
    expect(figures.getAllByText("—").length).toBeGreaterThanOrEqual(2);
  });

  it("a finished filesystem run that found no certificate says so, instead of drawing empty bars", async () => {
    const empty = makeDashboardSummary(fsRun, {
      totals: { ...makeDashboardSummary(fsRun).totals, unique_certificates: 0, sightings: 0 },
      validity: { at_discovery: { valid: 0, expiring: 0, expired: 0, not_yet_valid: 0 }, now: { unique: { valid: 0, expiring: 0, expired: 0, not_yet_valid: 0 }, sightings: { valid: 0, expiring: 0, expired: 0, not_yet_valid: 0 } } },
      algorithms: { top: [], other: null, total_groups: 0, limit: 10 }, signature_algorithms: { top: [], other: null, total_groups: 0, limit: 10 },
    });
    show(world({ dashboard: makeDashboard(fsRun, { summary: empty }) }));
    await screen.findByRole("figure", { name: "Certificate validity" });
    expect(screen.getAllByText("No certificate was found in this run.")).toHaveLength(3);
  });

  it("a filesystem run that did not complete cleanly warns that empty does not mean none", async () => {
    const partial = makeRun({ run_number: 6, status: "partial", error_summary: "roots_not_scanned:1" });
    show(world({ dashboard: makeDashboard(partial) }));
    expect(await screen.findByText(/did not complete cleanly, so an empty chart does not mean there are no certificates/)).toBeTruthy();
  });

  it("TLS charts say so when no handshake negotiated a version or cipher", async () => {
    show(world({ tlsSummaries: { [tlsNew.run_id]: makeTlsSummary(tlsNew) } }));
    expect(await screen.findByText("No completed handshake reported a TLS version.")).toBeTruthy();
    expect(screen.getByText("No completed handshake reported a cipher suite.")).toBeTruthy();
  });
});

describe("loading and failure", () => {
  it("says it is loading each part, then shows them", async () => {
    show(world());
    expect(screen.getAllByText(/Loading /).length).toBeGreaterThanOrEqual(3);
    await screen.findByRole("figure", { name: "TLS versions" });
    expect(screen.queryByText(/Loading /)).toBeNull();
  });

  it("one failing request does not blank the others, and Try again recovers it", async () => {
    const { be, user } = show(world({ failing: new Set(["dashboard"]) }));
    expect(await screen.findByText(/Could not load the certificate charts/)).toBeTruthy();
    expect(screen.getByRole("figure", { name: "Runs by status and type" })).toBeTruthy();       // the other parts are unaffected
    expect(await screen.findByRole("figure", { name: "TLS versions" })).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();                                                // a quiet message, not an alarm
    be.failing.delete("dashboard");
    await user.click(screen.getAllByRole("button", { name: "Try again" })[0]);
    expect(await screen.findByRole("figure", { name: "Certificate validity" })).toBeTruthy();
    expect(screen.queryByText(/Could not load the certificate charts/)).toBeNull();
  });

  it("a failing TLS summary or run list is reported for the TLS part only", async () => {
    show(world({ failing: new Set(["tlsSummary"]) }));
    expect(await screen.findByText(/Could not load the TLS charts/)).toBeTruthy();
    expect(await screen.findByRole("figure", { name: "Certificate validity" })).toBeTruthy();
    expect(screen.getByRole("figure", { name: "Runs by status and type" })).toBeTruthy();
  });

  it("an unusable answer is reported, not drawn", async () => {
    installFetch((req) => (req.path === "/api/runs/stats" ? new Response(JSON.stringify({ by_type_status: "nope" }), { status: 200, headers: { "Content-Type": "application/json" } }) : (dashboardBackend(world()).handler(req) ?? errorResponse(404, "not_found"))));
    render(<DashboardPage />);
    expect((await screen.findAllByText(/Could not load the run counts/)).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByRole("figure", { name: "Runs by status and type" })).toBeNull();
  });

  it("Refresh asks for everything again", async () => {
    const { fetchMock, user } = show(world());
    await screen.findByRole("figure", { name: "TLS versions" });
    const before = fetchMock.mock.calls.length;
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(before + 4));
    expect(urls(fetchMock).filter((u) => u === "/api/dashboard")).toHaveLength(2);
  });
});

describe("what the page does not do", () => {
  it("does not poll: nothing is requested after the first load until Refresh", async () => {
    vi.useFakeTimers();
    const be = dashboardBackend(world());
    const fetchMock = installFetch((req) => be.handler(req) ?? errorResponse(404, "not_found"));
    render(<DashboardPage />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    const first = fetchMock.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(fetchMock.mock.calls.length).toBe(first);
    vi.useRealTimers();
  });

  it("never offers an action that changes anything (no POST, PATCH or DELETE)", async () => {
    const { fetchMock } = show(world());
    await screen.findByRole("figure", { name: "TLS versions" });
    expect(fetchMock.mock.calls.every(([, init]) => !init?.method || init.method === "GET")).toBe(true);
  });
});
