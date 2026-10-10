// Contract test against REAL backend responses. real-report.json was captured from the real API app with the real agent and
// scanner (a certificate tree with PEM/DER/PFX files and key-only files; a run whose folder does not exist; a run with one good
// and one missing folder). Only the temporary folder prefix was replaced by C:\certs-root. Nothing in it is hand-written, so these
// tests fail if the frontend's types or wording drift from what the backend really sends.
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Run } from "../api/types";
import real from "../test/fixtures/real-report.json";
import { errorResponse, installFetch, jsonResponse, type Req } from "../test/helpers";
import { ReportPage } from "./ReportPage";

afterEach(() => {
  vi.unstubAllGlobals();
});

type Captured = (typeof real)["completed"] | (typeof real)["failed"] | (typeof real)["partial"];

function serve(...captured: Captured[]) {
  return (req: Req): Response => {
    for (const c of captured) {
      const id = (c.run as Run).run_id;
      const page = (p: { items: unknown[]; total: number; limit: number; offset: number }, items = p.items) => ({ ...p, items, total: items.length });
      if (req.path === `/api/runs/${id}`) return jsonResponse({ run: c.run });
      if (req.path === `/api/runs/${id}/fs/summary`) return jsonResponse(c.summary);
      if (req.path === `/api/runs/${id}/fs/certificates`) return jsonResponse(c.certificates);
      if (req.path === `/api/runs/${id}/issues`) return jsonResponse(c.issues);
      if (req.path === `/api/runs/${id}/fs/observations`) {
        const fp = req.query.get("fingerprint");
        const items = fp ? (c.observations.items as Array<{ sha256: string | null }>).filter((o) => o.sha256?.startsWith(fp)) : c.observations.items;
        return jsonResponse(page(c.observations as never, items));
      }
    }
    if (req.path === `/api/certificates/${real.detail_sha256}`) return jsonResponse(real.detail);
    return errorResponse(404, "run_not_found");
  };
}

describe("real completed run", () => {
  const c = real.completed;

  it("renders the counts and certificates exactly as the backend produced them", async () => {
    installFetch(serve(c));
    render(<ReportPage runId={(c.run as Run).run_id} />);
    const summary = await screen.findByRole("heading", { name: "Summary" });
    const stats = within(summary.closest("section")!);
    expect(stats.getByText("Records").nextSibling?.textContent).toBe(String(c.summary.totals.records));
    expect(stats.getByText("Certificate sightings").nextSibling?.textContent).toBe(String(c.summary.totals.sightings));
    expect(stats.getByText("Unique certificates").nextSibling?.textContent).toBe(String(c.summary.totals.unique_certificates));
    expect(c.summary.totals.records).toBeGreaterThan(c.summary.totals.sightings); // key-only files are records without a certificate

    const table = await screen.findByRole("table", { name: /Unique certificates/ });
    for (const cert of c.certificates.items) {
      expect(within(table).getAllByTitle(cert.sha256).length).toBeGreaterThan(0);
      expect(within(table).getAllByText(cert.subject).length).toBeGreaterThan(0);
    }
    expect(within(screen.getByRole("status", { name: "Run outcome" })).getByText("Completed")).toBeTruthy();
    expect(screen.getByText("C:\\certs-root\\certs")).toBeTruthy(); // the scope
  });

  it("lists key-only files as files without a certificate, and never shows key material", async () => {
    installFetch(serve(c));
    const user = userEvent.setup();
    render(<ReportPage runId={(c.run as Run).run_id} />);
    await user.click(await screen.findByRole("tab", { name: "Files" }));
    const table = await screen.findByRole("table", { name: /File records/ });
    const keyOnly = (c.observations.items as Array<{ parse_status: string; filename: string }>).filter((o) => o.parse_status === "no_certificate");
    expect(keyOnly.length).toBeGreaterThan(0);
    for (const row of keyOnly) {
      expect(within(within(table).getByRole("row", { name: new RegExp(row.filename.replace(".", "\\.")) })).getByText("No certificate in file")).toBeTruthy();
    }
    expect(document.body.textContent).not.toMatch(/PRIVATE KEY|BEGIN /);
  });

  it("opens a certificate and shows its real detail and this run's locations", async () => {
    installFetch(serve(c));
    const user = userEvent.setup();
    render(<ReportPage runId={(c.run as Run).run_id} />);
    const first = c.certificates.items[0];
    await user.click(await screen.findByRole("button", { name: first.subject }));
    const panel = await screen.findByRole("region", { name: "Certificate details" });
    expect(await within(panel).findByText(real.detail.serial_hex)).toBeTruthy();
    expect(within(panel).getAllByText(first.subject).length).toBeGreaterThan(0);
    const here = (c.observations.items as Array<{ sha256: string | null; path: string }>).filter((o) => o.sha256 === first.sha256);
    expect(here.length).toBeGreaterThan(0);
    for (const o of here) expect((await within(panel).findAllByText(o.path)).length).toBeGreaterThan(0);
  });
});

describe("real failed run (the folder does not exist)", () => {
  const c = real.failed;

  it("is shown as failed with the real reasons, and an empty list is not presented as 'none exist'", async () => {
    expect((c.run as Run).stop_reason).toBe("completed"); // exactly the case that misled the runs table
    installFetch(serve(c));
    render(<ReportPage runId={(c.run as Run).run_id} />);
    const banner = await screen.findByRole("status", { name: "Run outcome" });
    expect(within(banner).getByText("Failed")).toBeTruthy();
    expect(within(banner).getByText("No usable results were produced.")).toBeTruthy();
    expect(within(banner).getByText("1 folder could not be scanned.")).toBeTruthy();
    expect(within(banner).getByText("1 read error was recorded.")).toBeTruthy();
    expect(banner.className).toContain("banner-bad");
    expect(await screen.findByText(/did not complete cleanly, so an empty list does not mean there are none/)).toBeTruthy();
  });

  it("lists the recorded issue with the folder that was missing", async () => {
    installFetch(serve(c));
    const user = userEvent.setup();
    render(<ReportPage runId={(c.run as Run).run_id} />);
    await user.click(await screen.findByRole("tab", { name: "Issues" }));
    const issue = c.issues.items[0] as { source: string; kind: string; code: string; path: string };
    const table = await screen.findByRole("table", { name: /Issues recorded/ });
    expect(within(table).getByText(issue.code)).toBeTruthy();
    expect(within(table).getByText(issue.path)).toBeTruthy();
    expect(within(table).getByText(issue.source)).toBeTruthy();
  });
});

describe("real partial run (one folder scanned, one missing)", () => {
  const c = real.partial;

  it("is shown as partial, explains why, and still lists what was found", async () => {
    installFetch(serve(c));
    render(<ReportPage runId={(c.run as Run).run_id} />);
    const banner = await screen.findByRole("status", { name: "Run outcome" });
    expect(within(banner).getByText(/Partial - results are incomplete/)).toBeTruthy();
    expect(within(banner).getByText("1 folder could not be scanned.")).toBeTruthy();
    expect(banner.className).toContain("banner-warn");
    expect(await screen.findByRole("table", { name: /Unique certificates/ })).toBeTruthy();
  });
});
