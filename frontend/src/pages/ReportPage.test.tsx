import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Run } from "../api/types";
import { errorResponse, installFetch, jsonResponse, makeRun, queuedRun, runningRun } from "../test/helpers";
import { makeCert, makeDetail, makeIssue, makeKeyOnly, makeSighting, makeSummary, reportBackend, sha, type RunData } from "../test/reportBackend";
import { ReportPage } from "./ReportPage";

afterEach(() => {
  vi.unstubAllGlobals();
});

const urls = (mock: ReturnType<typeof installFetch>) => mock.mock.calls.map(([u]) => String(u));
const banner = () => screen.getByRole("status", { name: "Run outcome" });

function show(run: Run, data: RunData = {}, details = {}, extraRuns: Run[] = []) {
  const be = reportBackend([run, ...extraRuns], { [run.run_id]: data }, details);
  const fetchMock = installFetch(be.handler);
  const user = userEvent.setup();
  render(<ReportPage runId={run.run_id} />);
  return { user, fetchMock, be };
}

describe("a completed run", () => {
  const run = makeRun({ run_number: 7, config: { roots: ["C:\\certs", "D:\\more"] }, record_count: 3, finding_count: 2 });
  const certs = [
    makeCert(1, { subject: "CN=alpha.example", sightings: 2, paths: 2, key_algorithm: "EC", key_size: null, key_curve: "P-256" }),
    makeCert(2, { subject: "CN=beta.example", not_after: "2031-06-30T12:00:00Z" }),
  ];
  const data: RunData = {
    summary: makeSummary(run, { records: 3, sightings: 2, unique_certificates: 2, duplicate_observations: { total: 1, within_file: 0, across_files: 1 }, no_certificate: 1 }),
    certs,
    sightings: [makeSighting(0), makeSighting(1, { duplicate_kind: "across_files" }), makeKeyOnly(2)],
  };

  it("shows the run, its outcome, the summary and the certificates it found", async () => {
    show(run, data);
    expect(await screen.findByRole("heading", { level: 1, name: /Run #7/ })).toBeTruthy();
    expect(screen.getByText("C:\\certs")).toBeTruthy();
    expect(screen.getByText("D:\\more")).toBeTruthy();
    expect(within(banner()).getByText("Completed")).toBeTruthy();
    expect(within(banner()).getByText(/no errors were recorded/)).toBeTruthy();

    const summary = await screen.findByRole("heading", { name: "Summary" });
    const stats = within(summary.closest("section")!);
    expect(stats.getByText("Records").nextSibling?.textContent).toBe("3");
    expect(stats.getByText("Certificate sightings").nextSibling?.textContent).toBe("2");
    expect(stats.getByText("Unique certificates").nextSibling?.textContent).toBe("2");
    expect(stats.getByText("Files without a certificate").nextSibling?.textContent).toBe("1");

    const table = await screen.findByRole("table", { name: /Unique certificates/ });
    const alpha = within(within(table).getByRole("row", { name: /alpha\.example/ }));
    expect(alpha.getByText("CN=Example CA")).toBeTruthy();
    expect(alpha.getByText("EC P-256")).toBeTruthy();
    expect(alpha.getAllByText("2034-01-01").length).toBeGreaterThan(0);
    expect(alpha.getByText(sha(1).slice(0, 16) + "\u2026").getAttribute("title")).toBe(sha(1)); // the whole fingerprint stays available
    expect(within(table).getByText("2031-06-30")).toBeTruthy();
  });

  it("lists every file record, including files that held no certificate, and shows missing metadata as a dash", async () => {
    const { user } = show(run, data);
    await user.click(await screen.findByRole("tab", { name: "Files" }));
    const table = await screen.findByRole("table", { name: /File records/ });
    const keyRow = within(within(table).getByRole("row", { name: /file2\.pem/ }));
    expect(keyRow.getByText("No certificate in file")).toBeTruthy();
    expect(keyRow.getByText("no_certificate_block")).toBeTruthy();
    expect(keyRow.getAllByText("\u2014").length).toBeGreaterThanOrEqual(3); // subject, issuer, valid until, key... are not available
    const certRow = within(within(table).getByRole("row", { name: /file1\.pem/ }));
    expect(certRow.getByText("Also in another file")).toBeTruthy();
    expect(certRow.getByText("2600 days left at discovery")).toBeTruthy();
  });

  it("shows known warnings in words", async () => {
    const withWarning = { ...data, sightings: [makeSighting(0, { format: "pkcs12", evidence_confidence: "medium", warnings: ["pkcs12_integrity_not_verified"] })] };
    const { user } = show(run, withWarning);
    await user.click(await screen.findByRole("tab", { name: "Files" }));
    expect(await screen.findByText("PKCS#12 integrity (MAC) was not verified")).toBeTruthy();
  });

  it("offers a way back to the runs list", async () => {
    show(run, data);
    const link = await screen.findByRole("link", { name: /Discovery runs/ });
    expect(link.getAttribute("href")).toBe("#/runs");
  });
});

describe("certificate details", () => {
  const run = makeRun({ run_number: 2 });
  const other = makeRun({ run_number: 3 });
  const data: RunData = { certs: [makeCert(1)], sightings: [makeSighting(0), makeSighting(5, { sha256: sha(9), path: "C:\\certs\\unrelated.pem" })], summary: makeSummary(run, { records: 2, sightings: 2, unique_certificates: 2 }) };

  it("shows the certificate's facts and where THIS run found it, never another run's paths", async () => {
    const detail = makeDetail(1, { runs_total: 3, sightings_total: 5 });
    (detail as unknown as { runs: unknown[] }).runs = [
      { run_id: other.run_id, run_number: 3, sightings: 4, paths_count: 1, paths: ["C:\\other-run\\secret-location.pem"], paths_truncated: false },
    ];
    const sightings = [makeSighting(0, { sha256: sha(1), path: "C:\\certs\\one.pem" }), makeSighting(1, { sha256: sha(2), path: "C:\\certs\\two.pem" })];
    const { user, fetchMock } = show(run, { ...data, sightings }, { [sha(1)]: detail }, [other]);
    await user.click(await screen.findByRole("button", { name: "CN=host1.example" }));

    const panel = await screen.findByRole("region", { name: "Certificate details" });
    expect(await within(panel).findByText("0a1b2c3d")).toBeTruthy(); // serial
    expect(within(panel).getByText("host1.example")).toBeTruthy(); // SAN
    expect(within(panel).getByText("10.0.0.5")).toBeTruthy();
    expect(within(panel).getByText("No")).toBeTruthy(); // not a CA
    expect(within(panel).getByText("Also seen in 2 other runs")).toBeTruthy();
    expect(await within(panel).findByText("C:\\certs\\one.pem")).toBeTruthy();
    expect(within(panel).queryByText("C:\\certs\\two.pem")).toBeNull(); // a different certificate
    expect(screen.queryByText(/secret-location/)).toBeNull(); // other runs are counted, never listed

    const lookups = urls(fetchMock).filter((u) => u.includes("fingerprint="));
    expect(lookups).toHaveLength(1);
    expect(lookups[0]).toContain(`/api/runs/${run.run_id}/fs/observations?`);
    expect(lookups[0]).toContain(`fingerprint=${sha(1)}`);
  });

  it("says when the certificate authority flag or SANs were not recorded, and closes again", async () => {
    const { user } = show(run, { ...data, sightings: [makeSighting(0, { sha256: sha(1) })] }, { [sha(1)]: makeDetail(1, { is_ca: null, san: [] }) });
    await user.click(await screen.findByRole("button", { name: "CN=host1.example" }));
    const panel = await screen.findByRole("region", { name: "Certificate details" });
    expect(await within(panel).findByText("Not recorded")).toBeTruthy();
    expect(within(panel).getByText("None recorded")).toBeTruthy();
    expect(within(panel).getByText("Not seen in any other run")).toBeTruthy();
    await user.click(within(panel).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("region", { name: "Certificate details" })).toBeNull();
  });

  it("shows an error with Retry when the certificate cannot be loaded", async () => {
    const { user } = show(run, { ...data, sightings: [makeSighting(0, { sha256: sha(1) })] }, {}); // no detail: 404 certificate_not_found
    await user.click(await screen.findByRole("button", { name: "CN=host1.example" }));
    const panel = await screen.findByRole("region", { name: "Certificate details" });
    expect((await within(panel).findAllByRole("alert"))[0].textContent).toMatch(/refused the request \(404 certificate_not_found\)/);
  });
});

describe("states that must not look like a clean empty result", () => {
  it("a completed run that reported no records says so, without claiming that no files existed", async () => {
    const run = makeRun({ run_number: 1, record_count: 0, finding_count: 0 });
    show(run, { summary: makeSummary(run) });
    expect(await screen.findByText(/agent reported no records for this run, so there is nothing to list/)).toBeTruthy();
    expect(within(banner()).getByText(/agent reported no records/)).toBeTruthy();
    expect(screen.queryByText(/no certificate files/i)).toBeNull();
  });

  it("a failed run shows its reasons, a failure banner, and an empty list that is not presented as 'none exist'", async () => {
    const run = makeRun({ run_number: 4, status: "failed", stop_reason: "completed", error_summary: "no_usable_data, roots_not_scanned:1, file_errors:1", record_count: 0, finding_count: 0, error_count: 1 });
    show(run, { summary: makeSummary(run), issues: [makeIssue()] });
    expect(await screen.findByRole("status", { name: "Run outcome" })).toBeTruthy();
    const b = within(banner());
    expect(b.getByText("Failed")).toBeTruthy();
    expect(b.getByText(/No results were recorded\. An empty report here does not mean that no certificates exist\./)).toBeTruthy();
    expect(b.getByText("No usable results were produced.")).toBeTruthy();
    expect(b.getByText("1 folder could not be scanned.")).toBeTruthy();
    expect(await screen.findByText(/did not complete cleanly, so an empty list does not mean there are none/)).toBeTruthy();
    expect(screen.queryByText(/no errors were recorded/)).toBeNull();
    expect(banner().className).toContain("banner-bad");
  });

  it("a failed run that stored some records warns that they are incomplete", async () => {
    const run = makeRun({ run_number: 4, status: "failed", error_summary: "agent_lost", record_count: 5, finding_count: 5 });
    show(run, { summary: makeSummary(run, { records: 5, sightings: 5 }), certs: [makeCert(1)] });
    expect(await screen.findByText(/5 records were stored before the run failed/)).toBeTruthy();
  });

  it("a partial run is flagged incomplete with every reason", async () => {
    const run = makeRun({ run_number: 5, status: "partial", stop_reason: "completed", error_summary: "roots_not_scanned:1, file_errors:2", record_count: 1, finding_count: 1, error_count: 2 });
    show(run, { summary: makeSummary(run, { records: 1, sightings: 1, unique_certificates: 1 }), certs: [makeCert(1)] });
    expect(await screen.findByText(/Partial - results are incomplete/)).toBeTruthy();
    const b = within(banner());
    expect(b.getByText("1 folder could not be scanned.")).toBeTruthy();
    expect(b.getByText("2 read errors were recorded.")).toBeTruthy();
    expect(banner().className).toContain("banner-warn");
    expect(await screen.findByRole("table", { name: /Unique certificates/ })).toBeTruthy(); // what was found is still listed
  });

  it("a cancelled run is called cancelled, whichever way the backend recorded it", async () => {
    const partial = makeRun({ run_number: 6, status: "partial", stop_reason: "cancelled", error_summary: "stopped_cancelled", cancel_requested: true });
    show(partial, { summary: makeSummary(partial) });
    expect(await screen.findByText("Cancelled - results are incomplete")).toBeTruthy();
    expect(within(banner()).getByText("The scan was cancelled before it finished.")).toBeTruthy();
  });

  it("a run cancelled while queued is a cancelled failure with no results", async () => {
    const failed = makeRun({ run_number: 6, status: "failed", stop_reason: "cancelled", error_summary: "cancelled", cancel_requested: true, record_count: 0 });
    show(failed, { summary: makeSummary(failed) });
    expect(await screen.findByText("Cancelled before any results were recorded")).toBeTruthy();
  });

  it("a queued run has no results to show and does not request any", async () => {
    const run = queuedRun(8, { queued_at: new Date().toISOString() });
    const { fetchMock } = show(run);
    expect(await screen.findByRole("status", { name: "Run outcome" })).toBeTruthy();
    expect(within(banner()).getByText("Queued")).toBeTruthy();
    expect(within(banner()).getByText(/no results yet/)).toBeTruthy();
    expect(screen.queryByRole("tab")).toBeNull();
    expect(urls(fetchMock).filter((u) => u.includes("/fs/") || u.includes("/issues"))).toEqual([]);
  });

  it("a run that has waited a while for an agent says how to start one", async () => {
    show(queuedRun(8)); // queued in March, long before "now"
    expect(await within(await screen.findByRole("status", { name: "Run outcome" })).findByText(/No agent has picked this run up yet\. Start one with python -m agent/)).toBeTruthy();
  });

  it("a running run is marked as in progress and its numbers as incomplete", async () => {
    const run = runningRun(9, { record_count: 2, finding_count: 2 });
    show(run, { summary: makeSummary(run, { records: 2, sightings: 2, unique_certificates: 1 }), certs: [makeCert(1)] });
    expect(await screen.findByText("Scan in progress")).toBeTruthy();
    expect(within(banner()).getByText(/incomplete and will keep changing/)).toBeTruthy();
    expect(await screen.findByRole("table", { name: /Unique certificates/ })).toBeTruthy();
  });

  it("an unrecognised status makes no claim", async () => {
    const run = makeRun({ run_number: 1, status: "exploded" });
    show(run, { summary: makeSummary(run) });
    expect(await screen.findByText("Unknown status")).toBeTruthy();
    expect(screen.queryByText(/no errors were recorded/)).toBeNull();
  });

  it("an empty issues list on a completed run says no issues were recorded", async () => {
    const run = makeRun({ run_number: 1 });
    const { user } = show(run, { summary: makeSummary(run, { records: 1, sightings: 1 }), certs: [makeCert(1)] });
    await user.click(await screen.findByRole("tab", { name: "Issues" }));
    expect(await screen.findByText("No issues were recorded for this run.")).toBeTruthy();
  });

  it("lists recorded issues with who reported them", async () => {
    const run = makeRun({ run_number: 1, status: "partial", error_summary: "roots_not_scanned:1, file_errors:1", error_count: 1 });
    const { user } = show(run, { summary: makeSummary(run), issues: [makeIssue(), makeIssue({ source: "backend", kind: "rejected_record", code: "bad_field", path: null, seq: 12 })] });
    await user.click(await screen.findByRole("tab", { name: "Issues" }));
    const table = await screen.findByRole("table", { name: /Issues recorded/ });
    expect(within(table).getByText("FileNotFoundError:WinError 2")).toBeTruthy();
    expect(within(table).getByText("C:\\gone")).toBeTruthy();
    const backendRow = within(within(table).getByRole("row", { name: /rejected_record/ }));
    expect(backendRow.getByText("12")).toBeTruthy();
  });
});

describe("loading and failures", () => {
  it("shows loading first", async () => {
    const run = makeRun({ run_number: 1 });
    installFetch(() => new Promise<Response>(() => {}));
    render(<ReportPage runId={run.run_id} />);
    expect(screen.getByText(/Loading run/)).toBeTruthy();
  });

  it("says plainly that an unknown run does not exist", async () => {
    installFetch(reportBackend([], {}).handler);
    render(<ReportPage runId={"f".repeat(32)} />);
    expect(await screen.findByText(/That run does not exist/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
    expect(screen.getByRole("link", { name: /Discovery runs/ })).toBeTruthy();
  });

  it("offers Retry when the run cannot be loaded, and recovers", async () => {
    const run = makeRun({ run_number: 1 });
    let up = false;
    const be = reportBackend([run], { [run.run_id]: { summary: makeSummary(run) } });
    installFetch((req) => (up ? be.handler(req) : errorResponse(503, "busy")));
    const user = userEvent.setup();
    render(<ReportPage runId={run.run_id} />);
    expect((await screen.findByRole("alert")).textContent).toMatch(/busy/i);
    up = true;
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { level: 1, name: /Run #1/ })).toBeTruthy();
  });

  it("reports an unreachable backend", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("Failed to fetch"))));
    render(<ReportPage runId={"a".repeat(32)} />);
    expect((await screen.findByRole("alert")).textContent).toMatch(/Cannot reach the backend/);
  });

  it("a failing summary does not hide the tables, and its Retry works", async () => {
    const run = makeRun({ run_number: 1 });
    let summaryUp = false;
    const be = reportBackend([run], { [run.run_id]: { summary: makeSummary(run, { records: 1, sightings: 1 }), certs: [makeCert(1)] } });
    installFetch((req) => (req.path.endsWith("/fs/summary") && !summaryUp ? errorResponse(503, "query_timeout") : be.handler(req)));
    const user = userEvent.setup();
    render(<ReportPage runId={run.run_id} />);
    expect(await screen.findByRole("table", { name: /Unique certificates/ })).toBeTruthy();
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/took too long/);
    summaryUp = true;
    await user.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { name: "Summary" })).toBeTruthy();
  });

  it("a failing certificate list shows an error with Retry inside its tab", async () => {
    const run = makeRun({ run_number: 1 });
    let up = false;
    const be = reportBackend([run], { [run.run_id]: { summary: makeSummary(run), certs: [makeCert(1)] } });
    installFetch((req) => (req.path.endsWith("/fs/certificates") && !up ? errorResponse(500, "internal_error") : be.handler(req)));
    const user = userEvent.setup();
    render(<ReportPage runId={run.run_id} />);
    const panel = await screen.findByRole("tabpanel");
    const alert = await within(panel).findByRole("alert");
    expect(alert.textContent).toMatch(/internal error/);
    up = true;
    await user.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(await within(panel).findByRole("table")).toBeTruthy();
  });

  // Changed with the TLS report (this test used to assert that a TLS run gets "TLS reports are not implemented"). A TLS run now gets
  // the TLS probe report, and still never requests a filesystem report endpoint.
  it("shows a TLS run as a TLS probe report and never requests a filesystem report for it", async () => {
    const tls = makeRun({ run_number: 3, type: "tls", config: {} });
    const { fetchMock } = show(tls);
    expect(await screen.findByRole("heading", { level: 1, name: /Run #3\s+TLS probe report/ })).toBeTruthy();
    expect(await screen.findByLabelText("How this TLS data was collected")).toBeTruthy();
    expect(urls(fetchMock).filter((u) => u.includes("/fs/") || /\/runs\/[0-9a-f]{32}\/issues/.test(u))).toEqual([]);
    expect(urls(fetchMock).some((u) => u.includes("/tls/summary"))).toBe(true);
    expect(screen.queryByText(/not implemented/)).toBeNull();
  });

  it("says plainly that it does not know a run type it cannot report", async () => {
    const odd = makeRun({ run_number: 3, type: "packet_capture" });
    const { fetchMock } = show(odd);
    expect(await screen.findByText(/does not know this type of run/)).toBeTruthy();
    expect(urls(fetchMock).filter((u) => u.includes("/fs/") || u.includes("/tls/"))).toEqual([]);
  });
});

describe("layout and safe rendering", () => {
  it("keeps very long paths and fingerprints whole in the page and in a tooltip", async () => {
    const longPath = `C:\\${"very-long-folder-name\\".repeat(14)}server.pem`;
    const run = makeRun({ run_number: 1, config: { roots: [longPath] } });
    const { user } = show(run, { summary: makeSummary(run, { records: 1, sightings: 1 }), certs: [makeCert(1)], sightings: [makeSighting(0, { path: longPath })] });
    await user.click(await screen.findByRole("tab", { name: "Files" }));
    const cell = await screen.findAllByTitle(longPath);
    expect(cell.length).toBeGreaterThan(0);
    expect(cell[0].textContent).toBe(longPath); // not truncated in the DOM; CSS wraps it
    expect(cell[0].className).toContain("path");
  });

  it("renders markup in certificate fields as text", async () => {
    const evil = "<img src=x onerror=alert(1)>CN=evil";
    const run = makeRun({ run_number: 1, error_summary: null });
    show(run, { summary: makeSummary(run, { records: 1, sightings: 1 }), certs: [makeCert(1, { subject: evil, issuer: "<script>alert(2)</script>" })] });
    expect(await screen.findByRole("button", { name: evil })).toBeTruthy();
    expect(screen.getByText("<script>alert(2)</script>")).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
  });

  it("falls back to the raw text for a parse status it does not know", async () => {
    const run = makeRun({ run_number: 1 });
    const { user } = show(run, { summary: makeSummary(run), sightings: [makeKeyOnly(0, { parse_status: "future_status" })] });
    await user.click(await screen.findByRole("tab", { name: "Files" }));
    expect(await screen.findByText("future_status")).toBeTruthy();
  });
});

describe("paging and filtering", () => {
  const run = makeRun({ run_number: 1, record_count: 120, finding_count: 120 });
  const certs = Array.from({ length: 120 }, (_, i) => makeCert(i + 1));

  it("pages through certificates, pinning the frontier of the first page for the later ones", async () => {
    const { user, fetchMock } = show(run, { summary: makeSummary(run, { records: 120, sightings: 120, unique_certificates: 120 }), certs });
    await screen.findByText("Showing 1\u201350 of 120");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("Showing 51\u2013100 of 120");
    const page2 = urls(fetchMock).filter((u) => u.includes("/fs/certificates")).at(-1)!;
    expect(page2).toContain("offset=50");
    expect(page2).toContain("frontier=10"); // the frontier the first page reported
    expect(screen.getByRole("button", { name: "CN=host51.example" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Previous" }));
    await screen.findByText("Showing 1\u201350 of 120");
    const back = urls(fetchMock).filter((u) => u.includes("/fs/certificates")).at(-1)!;
    expect(back).toContain("offset=0");
    expect(back).not.toContain("frontier="); // page 1 is not pinned, so it sees new data
  });

  it("orders certificates by expiry, soonest first, and asks for 50 at a time", async () => {
    const { fetchMock } = show(run, { summary: makeSummary(run), certs });
    await screen.findByRole("table", { name: /Unique certificates/ });
    const first = urls(fetchMock).find((u) => u.includes("/fs/certificates"))!;
    expect(first).toContain("sort=not_after");
    expect(first).toContain("direction=asc");
    expect(first).toContain("limit=50");
  });

  it("filters files, returns to the first page, and clears the filters", async () => {
    const sightings = [makeSighting(0), makeSighting(1, { validity_status: "expired" }), makeKeyOnly(2)];
    const { user, fetchMock } = show(run, { summary: makeSummary(run), sightings });
    await user.click(await screen.findByRole("tab", { name: "Files" }));
    await screen.findByRole("table", { name: /File records/ });

    await user.selectOptions(screen.getByLabelText("Result"), "no_certificate");
    await user.type(screen.getByLabelText(/Search/), "file2");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(urls(fetchMock).at(-1)).toContain("parse_status=no_certificate"));
    expect(urls(fetchMock).at(-1)).toContain("q=file2");
    expect(urls(fetchMock).at(-1)).toContain("offset=0");
    expect(await screen.findByText("file2.pem")).toBeTruthy();
    expect(screen.queryByText("file0.pem")).toBeNull();

    await user.clear(screen.getByLabelText(/Search/));
    await user.type(screen.getByLabelText(/Search/), "nothing-matches");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("No files match these filters.")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByText("file0.pem")).toBeTruthy();
  });

  it("keeps the unpinned first page when a run is still being scanned and refreshes it", async () => {
    // refreshes of page 1 must not carry a frontier, or they would never see new records
    const running = runningRun(2);
    const { fetchMock } = show(running, { summary: makeSummary(running), certs });
    await screen.findByRole("table", { name: /Unique certificates/ });
    expect(urls(fetchMock).filter((u) => u.includes("/fs/certificates")).every((u) => !u.includes("frontier="))).toBe(true);
  });
});

describe("everything is scoped to the selected run", () => {
  it("only ever requests report data for the run being shown", async () => {
    const a = makeRun({ run_number: 1 });
    const b = makeRun({ run_number: 2 });
    const { user, fetchMock } = show(a, { summary: makeSummary(a, { records: 1, sightings: 1 }), certs: [makeCert(1)], sightings: [makeSighting(0)], issues: [makeIssue()] }, { [sha(1)]: makeDetail(1) }, [b]);
    await screen.findByRole("table", { name: /Unique certificates/ });
    await user.click(screen.getByRole("button", { name: "CN=host1.example" }));
    await screen.findByRole("region", { name: "Certificate details" });
    await user.click(screen.getByRole("tab", { name: "Files" }));
    await screen.findByRole("table", { name: /File records/ });
    await user.click(screen.getByRole("tab", { name: "Issues" }));
    await screen.findByRole("table", { name: /Issues recorded/ });

    const runScoped = urls(fetchMock).filter((u) => u.startsWith("/api/runs/"));
    expect(runScoped.length).toBeGreaterThanOrEqual(5);
    for (const u of runScoped) {
      expect(u).toContain(a.run_id);
      expect(u).not.toContain(b.run_id);
    }
  });

  it("shows nothing of run A once run B is open, and ignores an answer from A that arrives late", async () => {
    const a = makeRun({ run_number: 1 });
    const b = makeRun({ run_number: 2 });
    const be = reportBackend([a, b], {
      [a.run_id]: { summary: makeSummary(a, { records: 1, sightings: 1 }), certs: [makeCert(1, { subject: "CN=only-in-run-A" })] },
      [b.run_id]: { summary: makeSummary(b, { records: 1, sightings: 1 }), certs: [makeCert(2, { subject: "CN=only-in-run-B" })] },
    });
    let releaseA: () => void = () => {};
    const gate = new Promise<void>((resolve) => (releaseA = resolve));
    installFetch(async (req) => {
      if (req.path === `/api/runs/${a.run_id}/fs/certificates`) await gate; // A's certificate list is slow
      return be.handler(req);
    });

    const view = render(<ReportPage key={a.run_id} runId={a.run_id} />);
    await screen.findByRole("heading", { level: 1, name: /Run #1/ });
    view.rerender(<ReportPage key={b.run_id} runId={b.run_id} />); // the user opens run B
    expect(await screen.findByRole("heading", { level: 1, name: /Run #2/ })).toBeTruthy();
    expect(await screen.findByRole("button", { name: "CN=only-in-run-B" })).toBeTruthy();

    releaseA(); // A's answer arrives now
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(screen.queryByText("CN=only-in-run-A")).toBeNull();
    expect(screen.getByRole("button", { name: "CN=only-in-run-B" })).toBeTruthy();
    expect(screen.queryByRole("heading", { level: 1, name: /Run #1/ })).toBeNull();
  });
});

describe("a late answer for something no longer shown is ignored", () => {
  it("does not let a slow unfiltered file list overwrite the filtered one", async () => {
    const run = makeRun({ run_number: 1 });
    const sightings = [makeSighting(0), makeKeyOnly(2)];
    const be = reportBackend([run], { [run.run_id]: { summary: makeSummary(run), sightings } });
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    let slowFirst = true;
    installFetch(async (req) => {
      if (req.path.endsWith("/fs/observations") && !req.query.get("parse_status") && slowFirst) {
        slowFirst = false;
        await gate; // the first (unfiltered) request is slow
      }
      return be.handler(req);
    });
    const user = userEvent.setup();
    render(<ReportPage runId={run.run_id} />);
    await user.click(await screen.findByRole("tab", { name: "Files" }));
    await user.selectOptions(await screen.findByLabelText("Result"), "no_certificate");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("file2.pem")).toBeTruthy();

    release(); // the unfiltered answer arrives now, after the filtered one is on screen
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(screen.queryByText("file0.pem")).toBeNull();
    expect(screen.getByText("file2.pem")).toBeTruthy();
  });
});

describe("a response in the wrong shape is an error, not a crash", () => {
  it("shows an error for an answer that is not a summary", async () => {
    const run = makeRun({ run_number: 1 });
    const be = reportBackend([run], { [run.run_id]: { certs: [] } });
    installFetch((req) => (req.path.endsWith("/fs/summary") ? jsonResponse({ nonsense: true }) : be.handler(req)));
    render(<ReportPage runId={run.run_id} />);
    expect((await screen.findAllByRole("alert"))[0].textContent).toMatch(/does not understand/);
  });
});
