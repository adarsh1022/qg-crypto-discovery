// Contract test against REAL backend responses. real-tls-report.json was captured from the real API app with the real agent,
// the real probe and real local servers (a TLS server presenting a 3-certificate chain, a plain-text listener, a listener that never
// answers); a scan with no listeners; and a scan whose listener enumeration failed. Only the process id and executable path (machine
// specific) were normalised. Nothing is hand-written, so these tests fail if the frontend's types or wording drift from what the
// backend really sends.
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Run } from "../api/types";
import real from "../test/fixtures/real-tls-report.json";
import { errorResponse, installFetch, jsonResponse, type Req } from "../test/helpers";
import { ReportPage } from "./ReportPage";

afterEach(() => {
  vi.unstubAllGlobals();
});

type Captured = (typeof real)["completed"] | (typeof real)["zero_listeners"] | (typeof real)["enumeration_failed"];

function serve(...captured: Captured[]) {
  return (req: Req): Response => {
    for (const c of captured) {
      const id = (c.run as Run).run_id;
      if (req.path === `/api/runs/${id}`) return jsonResponse({ run: c.run });
      if (req.path === `/api/runs/${id}/tls/summary`) return jsonResponse(c.summary);
      if (req.path === `/api/runs/${id}/tls/issues`) return jsonResponse(c.issues);
      if (req.path === `/api/runs/${id}/tls/observations`) {
        const fp = req.query.get("fingerprint");
        const items = fp ? (c.observations.items as Array<{ peer_certificates: Array<{ sha256: string }> }>).filter((o) => o.peer_certificates.some((p) => p.sha256.startsWith(fp))) : c.observations.items;
        return jsonResponse({ ...c.observations, items, total: items.length });
      }
    }
    if (req.path === `/api/certificates/${real.detail_sha256}`) return jsonResponse(real.detail);
    return errorResponse(404, "run_not_found");
  };
}

describe("a real completed TLS run", () => {
  const c = real.completed;

  it("renders the real counts, and separates the completed handshake from the probes that are not findings", async () => {
    installFetch(serve(c));
    render(<ReportPage runId={(c.run as Run).run_id} />);
    const section = (await screen.findByRole("heading", { name: "Summary" })).closest("section")!;
    const stat = (label: string) => within(section).getByText(label).nextSibling?.textContent;
    expect(stat("Probe attempts")).toBe(String(c.summary.totals.probe_attempts));
    expect(stat("Completed TLS handshakes")).toBe(String(c.summary.totals.handshakes_completed));
    expect(stat("Failed or inconclusive probes")).toBe(String(c.summary.totals.not_completed));
    expect(c.summary.totals.handshakes_completed).toBe(1);
    expect(c.summary.totals.not_completed).toBe(2);                                    // the plain-text and the silent listener
    expect(within(await screen.findByRole("status", { name: "Run outcome" })).getByText("Completed")).toBeTruthy();
    expect(screen.getByLabelText("How this TLS data was collected").textContent).toMatch(/Active local probe results, not observed traffic/);
  });

  it("shows the real certificate chain leaf first, and no certificate for the listeners that did not complete a handshake", async () => {
    installFetch(serve(c));
    render(<ReportPage runId={(c.run as Run).run_id} />);
    const table = await screen.findByRole("table", { name: /Active probe attempts/ });
    const items = c.observations.items as Array<{ handshake_outcome: string; dst_port: number; peer_certificates: Array<{ sha256: string; subject: string }> }>;
    const good = items.find((i) => i.handshake_outcome === "completed")!;
    expect(good.peer_certificates).toHaveLength(3);
    const goodRow = within(within(table).getByRole("row", { name: new RegExp(`127\\.0\\.0\\.1:${good.dst_port}`) }));
    expect(goodRow.getByText("TLS handshake completed")).toBeTruthy();
    expect(goodRow.getByRole("button", { name: good.peer_certificates[0].subject })).toBeTruthy();
    expect(goodRow.getByText(/\+2 in chain/)).toBeTruthy();
    for (const other of items.filter((i) => i.handshake_outcome !== "completed")) {
      expect(other.peer_certificates).toEqual([]);
      const row = within(within(table).getByRole("row", { name: new RegExp(`127\\.0\\.0\\.1:${other.dst_port}`) }));
      expect(row.getByText("Not a TLS finding")).toBeTruthy();
      expect(row.queryByRole("button")).toBeNull();
    }
    expect(document.body.textContent).not.toMatch(/PRIVATE KEY|BEGIN /);
  });

  it("opens the real certificate and shows its facts and this run's probe", async () => {
    installFetch(serve(c));
    const user = userEvent.setup();
    render(<ReportPage runId={(c.run as Run).run_id} />);
    const items = c.observations.items as Array<{ peer_certificates: Array<{ subject: string; sha256: string }>; dst_port: number }>;
    const leaf = items.find((i) => i.peer_certificates.length > 0)!.peer_certificates[0];
    await user.click(await screen.findByRole("button", { name: leaf.subject }));
    const panel = await screen.findByRole("region", { name: "Certificate details" });
    expect(await within(panel).findByText(real.detail.serial_hex)).toBeTruthy();
    expect(within(panel).getByText(leaf.sha256)).toBeTruthy();
    expect(await within(panel).findByText(/1 probe attempt returned this certificate/)).toBeTruthy();
  });
});

describe("a real scan with no listeners", () => {
  it("is a completed run with an honest empty result, not a failure and not 'no TLS services exist'", async () => {
    const z = real.zero_listeners;
    installFetch(serve(z));
    render(<ReportPage runId={(z.run as Run).run_id} />);
    expect(await screen.findByText(/The agent found no listening TCP sockets on this machine, so there was nothing to probe/)).toBeTruthy();
    expect(within(screen.getByRole("status", { name: "Run outcome" })).getByText("Completed")).toBeTruthy();
    expect(screen.queryByText(/no TLS services exist/)).toBeNull();
  });
});

describe("a real scan whose enumeration failed", () => {
  const f = real.enumeration_failed;

  it("is a failure with the real reasons, and says nothing was probed", async () => {
    expect((f.run as Run).status).toBe("failed");
    installFetch(serve(f));
    render(<ReportPage runId={(f.run as Run).run_id} />);
    const banner = await screen.findByRole("status", { name: "Run outcome" });
    expect(within(banner).getByText("Failed")).toBeTruthy();
    expect(within(banner).getByText("No usable results were produced.")).toBeTruthy();
    expect(within(banner).getByText(/could not read this machine's list of listening sockets/)).toBeTruthy();
    expect(within(banner).getByText("1 scan error was recorded.")).toBeTruthy();                 // a TLS run's error is a scan error, not a file read error
    expect(within(banner).queryByText(/read error/)).toBeNull();
    expect(banner.className).toContain("banner-bad");
    expect((await screen.findByText(/could not read the operating system's list of listening sockets, so nothing was probed/)).getAttribute("role")).toBe("alert");
    expect(screen.queryByText(/Listeners found/)).toBeNull();
  });

  it("lists the enumeration error in the issues tab", async () => {
    installFetch(serve(f));
    const user = userEvent.setup();
    render(<ReportPage runId={(f.run as Run).run_id} />);
    await user.click(await screen.findByRole("tab", { name: "Issues" }));
    const table = await screen.findByRole("table", { name: /Issues recorded for this TLS run/ });
    expect(within(table).getByText("table_unreadable")).toBeTruthy();
    expect(within(table).getByText("enumerate")).toBeTruthy();
  });
});
