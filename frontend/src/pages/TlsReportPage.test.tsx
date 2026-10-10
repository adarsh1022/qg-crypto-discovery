import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Issue } from "../api/reportTypes";
import type { Run } from "../api/types";
import { errorResponse, installFetch, jsonResponse, makeRun, queuedRun, runningRun } from "../test/helpers";
import { makeDetail, reportBackend, type RunData } from "../test/reportBackend";
import { SCAN_OK, makeInconclusive, makePeer, makeProbe, makeTlsSummary, sha } from "../test/tlsFixtures";
import { ReportPage } from "./ReportPage";

afterEach(() => {
  vi.unstubAllGlobals();
});

const urls = (mock: ReturnType<typeof installFetch>) => mock.mock.calls.map(([u]) => String(u));
const banner = () => screen.getByRole("status", { name: "Run outcome" });
const tlsRun = (over: Partial<Run> = {}) => makeRun({ run_number: 5, type: "tls", config: {}, record_count: 6, finding_count: 3, ...over });

/** A varied, plausible set of probe rows: 3 completed handshakes (one with a 3-certificate chain) and 3 results that are NOT findings. */
function rowsFor() {
  return [
    makeProbe(0, { dst_port: 8443, peer_certificates: [makePeer(1, 0), makePeer(2, 1), makePeer(3, 2)] }),
    makeProbe(1, { dst_port: 8444, tls_version: "TLS1.2", cipher_suite: "ECDHE-RSA-AES256-GCM-SHA384", pid: 77, process_name: null, exe_path: null, process_attribution: "not_found", peer_certificates: [makePeer(4)] }),
    makeProbe(2, { dst_port: 9443, pid: null, process_name: null, exe_path: null, process_attribution: "unavailable", evidence_confidence: "medium",
                   warnings: ["active_probe", "packet_counts_unavailable", "chain_unavailable"], peer_certificates: [makePeer(1, 0)] }),
    makeInconclusive(3, "failed", "handshake_failed", { dst_port: 9000 }),
    makeInconclusive(4, "incomplete", "connect_timeout", { dst_port: 9001 }),
    makeInconclusive(5, "alert", "tlsv1_alert_protocol_version", { dst_port: 9002 }),
  ];
}

function show(run: Run, data: RunData = {}, details = {}) {
  const be = reportBackend([run], { [run.run_id]: data }, details);
  const fetchMock = installFetch(be.handler);
  const user = userEvent.setup();
  render(<ReportPage runId={run.run_id} />);
  return { user, fetchMock };
}

function completedWorld() {
  const run = tlsRun();
  const observations = rowsFor();
  const summary = makeTlsSummary(run, {
    outcomes: { completed: 3, failed: 1, alert: 1, incomplete: 1, unknown: 0 }, tls_versions: { SSL3: 0, "TLS1.0": 0, "TLS1.1": 0, "TLS1.2": 1, "TLS1.3": 2 },
    cipher_suites: { top: [{ cipher_suite: "TLS_AES_256_GCM_SHA384", handshakes: 2 }, { cipher_suite: "ECDHE-RSA-AES256-GCM-SHA384", handshakes: 1 }], other: null, total_groups: 2, limit: 20 },
    process_attribution: { attributed: 1, not_found: 1, unavailable: 4 },
    certificate_validity: { expiring_days: { value: 30, source: "default" }, now: { valid: 2, expiring: 1, expired: 0, not_yet_valid: 0 } },
    scan: SCAN_OK,
  }, { probe_attempts: 6, handshakes_completed: 3, not_completed: 3, endpoints: 6, certificates_presented: 4, leaf_certificates: 2 });
  return { run, data: { tlsSummary: summary, tlsObservations: observations } as RunData };
}

// =========================================================================== the method is stated prominently
describe("what this data is", () => {
  it("states, prominently and on every TLS report, that these are active probe results and not traffic or trust", async () => {
    const { run, data } = completedWorld();
    show(run, data);
    const notice = await screen.findByLabelText("How this TLS data was collected");
    const text = notice.textContent ?? "";
    expect(text).toMatch(/Active local probe results, not observed traffic/);
    expect(text).toMatch(/one probe attempt/);
    expect(text).toMatch(/Direction is unknown/);
    expect(text).toMatch(/Packet counts are unavailable because packet capture is disabled/);
    expect(text).toMatch(/Only a completed handshake is a TLS finding/);
    expect(text).toMatch(/Trust.*not evaluated/);
  });

  it("is shown even for a queued run and a failed run", async () => {
    show(queuedRun(2, { type: "tls", config: {} }));
    expect(await screen.findByLabelText("How this TLS data was collected")).toBeTruthy();
  });

  it("never claims passive capture, trust or security in the page", async () => {
    const { run, data } = completedWorld();
    show(run, data);
    await screen.findByRole("table");
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/captured traffic|passively|sniff|trusted|\bsecure\b|\bverified\b|validated/i);
  });
});

// =========================================================================== a completed run
describe("a completed TLS run", () => {
  it("shows the run, its outcome and the counts that separate attempts, findings and non-findings", async () => {
    const { run, data } = completedWorld();
    show(run, data);
    expect(await screen.findByRole("heading", { level: 1, name: /Run #5\s+TLS probe report/ })).toBeTruthy();
    expect(screen.getByText("TLS listeners on this machine")).toBeTruthy();
    expect(within(banner()).getByText("Completed")).toBeTruthy();
    const section = (await screen.findByRole("heading", { name: "Summary" })).closest("section")!;
    const stat = (label: string) => within(section).getByText(label).nextSibling?.textContent;
    expect(stat("Probe attempts")).toBe("6");
    expect(stat("Completed TLS handshakes")).toBe("3");
    expect(stat("Failed or inconclusive probes")).toBe("3");
    expect(stat("Endpoints probed")).toBe("6");
    expect(stat("Certificates presented")).toBe("4");
    expect(stat("Leaf certificates")).toBe("2");
    expect(within(section).getByText(/Listeners found: 12\./)).toBeTruthy();
    expect(within(section).getByText(/Skipped by the local-target policy: 2\./)).toBeTruthy();
    expect(within(section).getAllByText("TLS_AES_256_GCM_SHA384").length).toBeGreaterThan(0);
  });

  it("shows a completed handshake with its version, cipher, certificate, chain and process", async () => {
    const { run, data } = completedWorld();
    show(run, data);
    const table = await screen.findByRole("table", { name: /Active probe attempts/ });
    const row = within(within(table).getAllByRole("row")[1]);
    expect(row.getByText("TLS handshake completed")).toBeTruthy();
    expect(row.queryByText("Not a TLS finding")).toBeNull();
    expect(row.getByText("127.0.0.1:8443")).toBeTruthy();
    expect(row.getByText("TLS1.3")).toBeTruthy();
    expect(row.getByText("TLS_AES_256_GCM_SHA384")).toBeTruthy();
    expect(row.getByRole("button", { name: "CN=tls1.example" })).toBeTruthy();
    expect(row.getAllByText(sha(1).slice(0, 16) + "\u2026")[0].getAttribute("title")).toBe(sha(1));        // the whole fingerprint is available
    expect(row.getByText(/\+2 in chain/)).toBeTruthy();
    expect(row.getByText(/until 2034-01-01/)).toBeTruthy();
    const process = row.getByText("svc.exe");
    expect(process.closest("span")?.getAttribute("title")).toBe("C:\\Program Files\\svc\\svc.exe");   // the executable path in a tooltip
    expect(row.getByText("(PID 4321)")).toBeTruthy();
  });

  it("keeps the executable path, sockets, counts and chain in an expandable detail, with the packet limitation spelled out", async () => {
    const { run, data } = completedWorld();
    const { user } = show(run, data);
    const table = await screen.findByRole("table", { name: /Active probe attempts/ });
    const row = within(within(table).getAllByRole("row")[1]);
    await user.click(row.getByText("Details"));
    expect(row.getByText(/Active probe attempt #1/)).toBeTruthy();
    expect(row.getByText(/direction unknown/)).toBeTruthy();
    expect(row.getByText(/probe socket 127\.0\.0\.1:50000 → listener 127\.0\.0\.1:8443/)).toBeTruthy();
    expect(row.getByText(/1 probe attempt; packet count 0 \(unavailable: no packet capture\)/)).toBeTruthy();
    expect(row.getByText("C:\\Program Files\\svc\\svc.exe", { selector: ".path" })).toBeTruthy();
    expect(row.getByText(/None sent \(the probe connects to an IP address\)/)).toBeTruthy();
    expect(row.getAllByText(/CN=tls[123]\.example/).length).toBe(4);                                  // the chain, leaf first (plus the row's own button)
  });

  it("shows process attribution honestly when the process is not found or unavailable", async () => {
    const { run, data } = completedWorld();
    show(run, data);
    const table = await screen.findByRole("table", { name: /Active probe attempts/ });
    const rows = within(table).getAllByRole("row");
    expect(within(rows[2]).getAllByText(/Process not found/).length).toBeGreaterThan(0);
    expect(within(rows[2]).getAllByText(/PID 77/).length).toBeGreaterThan(0);
    expect(within(rows[3]).getAllByText("Process unavailable").length).toBeGreaterThan(0);
  });

  it("explains a leaf-only chain through the row's warning", async () => {
    const { run, data } = completedWorld();
    show(run, data);
    const table = await screen.findByRole("table", { name: /Active probe attempts/ });
    expect(within(within(table).getAllByRole("row")[3]).getAllByText(/Only the leaf certificate was available/).length).toBeGreaterThan(0);   // the row and its details
  });
});

// =========================================================================== failed and inconclusive probes are not findings
describe("probes that are not TLS findings", () => {
  it("are labelled, in words, as not being a TLS finding and show no version, cipher or certificate", async () => {
    const { run, data } = completedWorld();
    show(run, data);
    const table = await screen.findByRole("table", { name: /Active probe attempts/ });
    const rows = within(table).getAllByRole("row");
    for (const [index, label] of [[4, "Handshake failed"], [5, "Probe incomplete"], [6, "TLS alert received"]] as const) {
      const row = within(rows[index]);
      expect(row.getByText(label)).toBeTruthy();
      expect(row.getByText("Not a TLS finding")).toBeTruthy();
      expect(row.queryByText("TLS handshake completed")).toBeNull();
      expect(row.queryByRole("button")).toBeNull();                                                     // no certificate to open
      expect(row.queryByText(/TLS1\.[0-3]/)).toBeNull();
    }
    expect(within(rows[4]).getAllByText(/The TLS handshake failed \(the service may not speak TLS\)/).length).toBeGreaterThan(0);
    expect(within(rows[5]).getAllByText("The connection attempt timed out").length).toBeGreaterThan(0);
    expect(within(rows[6]).getAllByText(/TLS alert \(tlsv1_alert_protocol_version\)/).length).toBeGreaterThan(0);
  });

  it("the constant method markers are not repeated as warnings on every row", async () => {
    const { run, data } = completedWorld();
    show(run, data);
    const table = await screen.findByRole("table", { name: /Active probe attempts/ });
    expect(within(table).queryAllByText(/Active probe attempt, not observed traffic/).length).toBe(6);    // only in the expandable details
  });

  it("filters to the probes that are not findings, or to completed ones, and returns to page one", async () => {
    const { run, data } = completedWorld();
    const { user, fetchMock } = show(run, data);
    await screen.findByRole("table", { name: /Active probe attempts/ });
    await user.selectOptions(screen.getByLabelText("Result"), "failed");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(urls(fetchMock).at(-1)).toContain("outcome=failed"));
    expect(urls(fetchMock).at(-1)).toContain("offset=0");
    const filtered = await screen.findByRole("table", { name: /Active probe attempts/ });
    await waitFor(() => expect(within(filtered).getAllByRole("row")).toHaveLength(2));            // header + the one failed probe
    expect(within(filtered).getByText("Handshake failed")).toBeTruthy();
    expect(within(filtered).queryByText("TLS handshake completed")).toBeNull();

    await user.selectOptions(screen.getByLabelText("Result"), "completed");
    await user.selectOptions(screen.getByLabelText("TLS version"), "TLS1.2");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    const row = await screen.findByRole("button", { name: "CN=tls4.example" });
    expect(row).toBeTruthy();
    await user.type(screen.getByLabelText(/Search/), "nothing-matches");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("No probe results match these filters.")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    const restored = await screen.findByRole("table", { name: /Active probe attempts/ });
    await waitFor(() => expect(within(restored).getAllByRole("row")).toHaveLength(7));            // header + all six probes again
    expect(within(restored).getAllByText("TLS handshake completed")).toHaveLength(3);
  });
});

// =========================================================================== run states
describe("states that must not look like a clean empty result", () => {
  it("a queued run shows the method and no results, and requests no report data", async () => {
    const run = queuedRun(8, { type: "tls", config: {}, queued_at: new Date().toISOString() });
    const { fetchMock } = show(run);
    expect(await screen.findByRole("status", { name: "Run outcome" })).toBeTruthy();
    expect(within(banner()).getByText("Queued")).toBeTruthy();
    expect(screen.queryByRole("tab")).toBeNull();
    expect(urls(fetchMock).filter((u) => u.includes("/tls/"))).toEqual([]);
  });

  it("a running run is marked as in progress and its numbers as incomplete", async () => {
    const run = runningRun(9, { type: "tls", config: {}, record_count: 2, finding_count: 1 });
    const probes = [makeProbe(0), makeInconclusive(1)];
    show(run, { tlsSummary: makeTlsSummary(run, {}, { probe_attempts: 2, handshakes_completed: 1, not_completed: 1 }), tlsObservations: probes });
    expect(await screen.findByText("Scan in progress")).toBeTruthy();
    expect(within(banner()).getByText(/incomplete and will keep changing/)).toBeTruthy();
    expect(await screen.findByRole("table", { name: /Active probe attempts/ })).toBeTruthy();
  });

  it("a partial run lists its reasons and still shows what was recorded", async () => {
    const run = tlsRun({ status: "partial", stop_reason: "completed", error_summary: "file_errors:1, stopped_target_limit", error_count: 1 });
    show(run, { tlsSummary: makeTlsSummary(run, { scan: { ...SCAN_OK, stop_reason: "target_limit", targets_truncated: true } }, { probe_attempts: 1, handshakes_completed: 1 }),
                tlsObservations: [makeProbe(0)] });
    expect(await screen.findByText(/Partial - results are incomplete/)).toBeTruthy();
    const b = within(banner());
    expect(b.getByText("1 scan error was recorded.")).toBeTruthy();                              // not "read error": no file was read
    expect(b.queryByText(/read error/)).toBeNull();
    expect(b.getByText("The target limit was reached, so not every listener was probed.")).toBeTruthy();
    expect(b.getByText(/Other listeners may exist that were not probed/)).toBeTruthy();
    expect(banner().className).toContain("banner-warn");
    expect(await screen.findByRole("table", { name: /Active probe attempts/ })).toBeTruthy();
    expect(screen.getByText(/The target limit was reached, so not every listener was probed\. /, { selector: "p" })).toBeTruthy();
  });

  it("a failed run with no results is not an empty success and is not described as 'no TLS services'", async () => {
    const run = tlsRun({ status: "failed", stop_reason: "boom", error_summary: "agent_lost", record_count: 0, finding_count: 0 });
    show(run, { tlsSummary: makeTlsSummary(run) });
    const b = within(await screen.findByRole("status", { name: "Run outcome" }));
    expect(b.getByText("Failed")).toBeTruthy();
    expect(b.getByText(/No probe results were recorded\. An empty report here does not mean that no TLS services exist\./)).toBeTruthy();
    expect(await screen.findByText(/did not complete cleanly, so an empty list does not mean there are no TLS services/)).toBeTruthy();
    expect(banner().className).toContain("banner-bad");
    expect(screen.queryByText(/no errors were recorded/)).toBeNull();
  });

  it("a failed enumeration is called out as a failure of the scan, not as 'no listeners'", async () => {
    const run = tlsRun({ status: "failed", stop_reason: "completed", error_summary: "no_usable_data, stopped_enumeration_failed, file_errors:1", record_count: 0, finding_count: 0, error_count: 1 });
    const scan = { stop_reason: "enumeration_failed", enumeration: "failed", listeners_found: 0, port_filtered: 0, policy_skipped: 0, targets_planned: 0, targets_probed: 0, targets_truncated: false };
    show(run, { tlsSummary: makeTlsSummary(run, { scan, issues: { errors: { total: 1, enumerate: 1, probe: 0 }, rejected: 0, seq_conflicts: 0 } }) });
    expect(await within(await screen.findByRole("status", { name: "Run outcome" })).findByText(/could not read this machine's list of listening sockets/)).toBeTruthy();
    const alert = await screen.findByText(/could not read the operating system's list of listening sockets, so nothing was probed/);
    expect(alert.getAttribute("role")).toBe("alert");
    expect(screen.queryByText(/Listeners found: 0/)).toBeNull();                       // a failed enumeration does not claim "0 listeners"
  });

  it("zero eligible listeners is a completed scan that says the agent found no listening sockets", async () => {
    const run = tlsRun({ record_count: 0, finding_count: 0 });
    show(run, { tlsSummary: makeTlsSummary(run, { scan: { ...SCAN_OK, listeners_found: 0, policy_skipped: 0, targets_planned: 0, targets_probed: 0 } }) });
    expect(await screen.findByText(/The agent found no listening TCP sockets on this machine, so there was nothing to probe/)).toBeTruthy();
    expect(within(banner()).getByText("Completed")).toBeTruthy();
    expect(screen.queryByText(/no TLS services exist/)).toBeNull();
  });

  it("listeners that were all skipped by policy are said so", async () => {
    const run = tlsRun({ record_count: 0, finding_count: 0 });
    show(run, { tlsSummary: makeTlsSummary(run, { scan: { ...SCAN_OK, listeners_found: 4, policy_skipped: 3, port_filtered: 1, targets_planned: 0, targets_probed: 0 } }) });
    expect(await screen.findByText(/found 4 listening sockets, but none was eligible to probe \(skipped by policy: 3, left out by the port list: 1\)/)).toBeTruthy();
  });

  it("a completed run with no results and no scan facts says only that the agent reported none", async () => {
    const run = tlsRun({ record_count: 0, finding_count: 0 });
    show(run, { tlsSummary: makeTlsSummary(run) });
    expect(await screen.findByText("The agent reported no probe results for this run.")).toBeTruthy();
  });

  it("an empty issues tab on a completed run says none were recorded", async () => {
    const { run, data } = completedWorld();
    const { user } = show(run, data);
    await user.click(await screen.findByRole("tab", { name: "Issues" }));
    expect(await screen.findByText("No issues were recorded for this run.")).toBeTruthy();
  });

  it("lists recorded scan errors and refusals", async () => {
    const run = tlsRun({ status: "partial", error_summary: "file_errors:1, records_rejected:1", error_count: 1, rejected_count: 1 });
    const issues: Issue[] = [{ source: "agent", kind: "probe", code: "target_not_local", path: null, seq: null }, { source: "backend", kind: "rejected_record", code: "bad_direction", path: null, seq: 3 }];
    const { user } = show(run, { tlsSummary: makeTlsSummary(run), tlsObservations: [makeProbe(0)], tlsIssues: issues });
    await user.click(await screen.findByRole("tab", { name: "Issues" }));
    const table = await screen.findByRole("table", { name: /Issues recorded for this TLS run/ });
    expect(within(table).getByText("target_not_local")).toBeTruthy();
    const refused = within(within(table).getByRole("row", { name: /rejected_record/ }));
    expect(refused.getByText("bad_direction")).toBeTruthy();
    expect(refused.getByText("3")).toBeTruthy();
  });
});

// =========================================================================== certificate panel
describe("certificate details", () => {
  it("shows the certificate's own facts and where THIS run's probes presented it, without filesystem sighting counts", async () => {
    const { run, data } = completedWorld();
    const { user, fetchMock } = show(run, data, { [sha(1)]: makeDetail(1, { runs_total: 4817, sightings_total: 9283 }) });
    await user.click((await screen.findAllByRole("button", { name: "CN=tls1.example" }))[0]);
    const panel = await screen.findByRole("region", { name: "Certificate details" });
    expect(await within(panel).findByText("0a1b2c3d")).toBeTruthy();                 // serial
    expect(within(panel).getByText("10.0.0.5")).toBeTruthy();                        // a SAN
    expect(within(panel).getByText(sha(1))).toBeTruthy();
    expect(await within(panel).findByText(/2 probe attempts returned this certificate/)).toBeTruthy();
    expect(within(panel).getByText(/127\.0\.0\.1:8443/)).toBeTruthy();
    expect(within(panel).getByText(/127\.0\.0\.1:9443/)).toBeTruthy();
    expect(within(panel).getAllByText(/Trust and host names are not evaluated/).length).toBeGreaterThan(0);
    expect(panel.textContent).not.toMatch(/other run|sightings|Also seen/i);          // the shared endpoint's filesystem counts are not shown
    expect(panel.textContent).not.toContain("4817");                                   // not its run count ...
    expect(panel.textContent).not.toContain("9283");                                   // ... and not its sighting count (they describe filesystem scans)
    const lookups = urls(fetchMock).filter((u) => u.includes("fingerprint="));
    expect(lookups).toHaveLength(1);
    expect(lookups[0]).toContain(`/api/runs/${run.run_id}/tls/observations?`);
    expect(lookups[0]).toContain(`fingerprint=${sha(1)}`);
  });

  it("shows an error with Retry when the certificate cannot be loaded, and closes again", async () => {
    const { run, data } = completedWorld();
    const { user } = show(run, data, {});                                              // no detail: 404 certificate_not_found
    await user.click((await screen.findAllByRole("button", { name: "CN=tls1.example" }))[0]);
    const panel = await screen.findByRole("region", { name: "Certificate details" });
    expect((await within(panel).findAllByRole("alert"))[0].textContent).toMatch(/404 certificate_not_found/);
    await user.click(within(panel).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("region", { name: "Certificate details" })).toBeNull();
  });
});

// =========================================================================== loading, errors, isolation
describe("loading and failures", () => {
  it("offers Retry when the summary fails, and the tabs still work", async () => {
    const { run, data } = completedWorld();
    let up = false;
    const be = reportBackend([run], { [run.run_id]: data });
    installFetch((req) => (req.path.endsWith("/tls/summary") && !up ? errorResponse(503, "query_timeout") : be.handler(req)));
    const user = userEvent.setup();
    render(<ReportPage runId={run.run_id} />);
    expect(await screen.findByRole("table", { name: /Active probe attempts/ })).toBeTruthy();
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/took too long/);
    up = true;
    await user.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { name: "Summary" })).toBeTruthy();
  });

  it("shows an error with Retry inside the results tab when the list fails, and recovers", async () => {
    const { run, data } = completedWorld();
    let up = false;
    const be = reportBackend([run], { [run.run_id]: data });
    installFetch((req) => (req.path.endsWith("/tls/observations") && !up ? errorResponse(500, "internal_error") : be.handler(req)));
    const user = userEvent.setup();
    render(<ReportPage runId={run.run_id} />);
    const panel = await screen.findByRole("tabpanel");
    const alert = await within(panel).findByRole("alert");
    expect(alert.textContent).toMatch(/internal error/);
    up = true;
    await user.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(await within(panel).findByRole("table")).toBeTruthy();
  });

  it("an unknown run does not exist, and a run of another type is not reported here", async () => {
    installFetch(reportBackend([], {}).handler);
    render(<ReportPage runId={"f".repeat(32)} />);
    expect(await screen.findByText(/That run does not exist/)).toBeTruthy();
  });

  it("shows loading first", async () => {
    installFetch(() => new Promise<Response>(() => {}));
    render(<ReportPage runId={"a".repeat(32)} />);
    expect(screen.getByText(/Loading run/)).toBeTruthy();
  });

  it("a response in the wrong shape is an error, not a crash", async () => {
    const { run, data } = completedWorld();
    const be = reportBackend([run], { [run.run_id]: data });
    installFetch((req) => (req.path.endsWith("/tls/summary") ? jsonResponse({ nonsense: true }) : be.handler(req)));
    render(<ReportPage runId={run.run_id} />);
    expect((await screen.findAllByRole("alert"))[0].textContent).toMatch(/does not understand/);
  });
});

describe("scope and safe rendering", () => {
  it("only ever requests TLS report data for the run being shown, never a filesystem report", async () => {
    const { run, data } = completedWorld();
    const other = makeRun({ run_number: 6, type: "tls", config: {} });
    const { user, fetchMock } = show(run, data, { [sha(1)]: makeDetail(1) });
    await screen.findByRole("table", { name: /Active probe attempts/ });
    await user.click(screen.getAllByRole("button", { name: "CN=tls1.example" })[0]);
    await screen.findByRole("region", { name: "Certificate details" });
    await user.click(screen.getByRole("tab", { name: "Issues" }));
    await screen.findByText("No issues were recorded for this run.");
    const scoped = urls(fetchMock).filter((u) => u.startsWith("/api/runs/"));
    expect(scoped.length).toBeGreaterThanOrEqual(4);
    for (const u of scoped) {
      expect(u).toContain(run.run_id);
      expect(u).not.toContain(other.run_id);
      expect(u).not.toMatch(/\/fs\/|\/runs\/[0-9a-f]{32}\/issues/);
    }
  });

  it("renders markup in process names, subjects and paths as text", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    const run = tlsRun({ record_count: 1, finding_count: 1 });
    show(run, { tlsSummary: makeTlsSummary(run), tlsObservations: [makeProbe(0, { process_name: evil, exe_path: `C:\\<script>alert(2)</script>`, peer_certificates: [makePeer(1, 0, { subject: evil })] })] });
    expect(await screen.findByRole("button", { name: evil })).toBeTruthy();
    expect(screen.getByText(evil, { selector: "span" })).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
  });

  it("keeps a very long executable path whole in the tooltip and the details", async () => {
    const longPath = `C:\\${"very-long-folder-name\\".repeat(14)}svc.exe`;
    const run = tlsRun({ record_count: 1, finding_count: 1 });
    const { user } = show(run, { tlsSummary: makeTlsSummary(run), tlsObservations: [makeProbe(0, { exe_path: longPath })] });
    await screen.findByRole("table", { name: /Active probe attempts/ });
    expect(screen.getByText("svc.exe").closest("span")?.getAttribute("title")).toBe(longPath);
    await user.click(screen.getByText("Details"));
    const shown = screen.getByText(longPath, { selector: ".path" });
    expect(shown.textContent).toBe(longPath);
  });

  it("an unrecognised outcome is shown as text and is not a finding", async () => {
    const run = tlsRun({ record_count: 1 });
    show(run, { tlsSummary: makeTlsSummary(run), tlsObservations: [makeInconclusive(0, "future_outcome", "x")] });
    expect(await screen.findByText("future_outcome")).toBeTruthy();
    expect(screen.getByText("Not a TLS finding")).toBeTruthy();
  });
});

describe("paging", () => {
  it("pages through the results, pinning the frontier of the first page for later ones", async () => {
    const run = tlsRun({ record_count: 120, finding_count: 120 });
    const probes = Array.from({ length: 120 }, (_, i) => makeProbe(i, { dst_port: 3000 + i, peer_certificates: [makePeer(i + 1)] }));
    const { user, fetchMock } = show(run, { tlsSummary: makeTlsSummary(run), tlsObservations: probes });
    await screen.findByText("Showing 1\u201350 of 120");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("Showing 51\u2013100 of 120");
    const page2 = urls(fetchMock).filter((u) => u.includes("/tls/observations")).at(-1)!;
    expect(page2).toContain("offset=50");
    expect(page2).toContain("frontier=10");
    await user.click(screen.getByRole("button", { name: "Previous" }));
    await screen.findByText("Showing 1\u201350 of 120");
    expect(urls(fetchMock).filter((u) => u.includes("/tls/observations")).at(-1)).not.toContain("frontier=");
  });
});
