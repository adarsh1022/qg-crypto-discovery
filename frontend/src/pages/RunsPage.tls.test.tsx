import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { backend } from "../test/fakeBackend";
import { installFetch, jsonResponse, makeRun, queuedRun } from "../test/helpers";
import { createdNotice, RunsPage } from "./RunsPage";

afterEach(() => {
  vi.unstubAllGlobals();
});

const rowFor = (n: number) => screen.getByRole("row", { name: new RegExp(`^#${n}\\b`) });

/** A backend that stores the run it was asked for, with the requested type and configuration, like the real one. */
function realisticBackend(initial = [] as ReturnType<typeof makeRun>[]) {
  const fake = backend(initial);
  const handler = (req: any) => {
    if (req.method === "POST" && req.path === "/api/runs") {
      const run = queuedRun(fake.runs.length + 1, { type: req.body.type, config: req.body.config });
      fake.runs.unshift(run);
      return jsonResponse({ run }, 201);
    }
    return fake.handler(req);
  };
  return { ...fake, handler };
}

describe("the New scan panel", () => {
  it("offers a filesystem scan and a TLS metadata scan, and shows the filesystem form first", async () => {
    installFetch(realisticBackend().handler);
    render(<RunsPage />);
    await screen.findByText(/No runs yet/);
    const tabs = within(screen.getByRole("tablist", { name: "Scan type" })).getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["Filesystem scan", "TLS metadata scan"]);
    expect(tabs[0].getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("button", { name: "Run filesystem scan" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Run TLS metadata scan" })).toBeNull(); // hidden panel: not available until chosen
  });

  it("switches to the TLS form and back without losing what was typed in either", async () => {
    installFetch(realisticBackend().handler);
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByText(/No runs yet/);
    await user.type(screen.getByLabelText(/Folders to scan/), "C:\\certs");
    await user.click(screen.getByRole("tab", { name: "TLS metadata scan" }));
    expect(screen.getByRole("tab", { name: "TLS metadata scan" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.queryByRole("button", { name: "Run filesystem scan" })).toBeNull();
    await user.type(screen.getByLabelText("Ports to probe"), "8443");
    await user.click(screen.getByRole("tab", { name: "Filesystem scan" }));
    expect((screen.getByLabelText(/Folders to scan/) as HTMLTextAreaElement).value).toBe("C:\\certs");
    await user.click(screen.getByRole("tab", { name: "TLS metadata scan" }));
    expect((screen.getByLabelText("Ports to probe") as HTMLInputElement).value).toBe("8443");
  });

  it("the tabs and their panels point at each other", async () => {
    installFetch(realisticBackend().handler);
    render(<RunsPage />);
    await screen.findByText(/No runs yet/);
    for (const [tab, panel] of [["Filesystem scan", "scan-panel-filesystem"], ["TLS metadata scan", "scan-panel-tls"]] as const) {
      const t = screen.getByRole("tab", { name: tab });
      expect(t.getAttribute("aria-controls")).toBe(panel);
      expect(document.getElementById(panel)?.getAttribute("aria-labelledby")).toBe(t.id);
    }
  });
});

describe("starting a TLS scan from the Runs page", () => {
  it("creates a TLS run with the ports entered, shows it queued with its type, scope and trigger, and closes the panel", async () => {
    const fetchMock = installFetch(realisticBackend().handler);
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByText(/No runs yet/);
    await user.click(screen.getByRole("tab", { name: "TLS metadata scan" }));
    await user.type(screen.getByLabelText("Ports to probe"), "8443 9443");
    await user.click(screen.getByRole("button", { name: "Run TLS metadata scan" }));

    expect(await screen.findByText(/Run #1 is queued/)).toBeTruthy();
    const post = fetchMock.mock.calls.find(([, i]) => i?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ type: "tls", config: { ports: [8443, 9443] } });
    const row = within(await screen.findByRole("row", { name: /^#1/ }));
    expect(row.getByText("Queued")).toBeTruthy();
    expect(row.getByText("tls")).toBeTruthy();
    expect(row.getByText("TLS listeners on this machine (ports 8443, 9443)")).toBeTruthy();
    expect(row.getByText("Manual")).toBeTruthy();
    const details = screen.getByText("New scan").closest("details") as HTMLDetailsElement;
    await waitFor(() => expect(details.open).toBe(false));
  });

  it("refuses to probe everything without the explicit opt-in, and sends nothing", async () => {
    const fetchMock = installFetch(realisticBackend().handler);
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByText(/No runs yet/);
    await user.click(screen.getByRole("tab", { name: "TLS metadata scan" }));
    await user.click(screen.getByRole("button", { name: "Run TLS metadata scan" }));
    expect(await screen.findByText(/at least one port, or tick the box/)).toBeTruthy();
    expect(fetchMock.mock.calls.filter(([, i]) => i?.method === "POST")).toHaveLength(0);
  });

  it("with the explicit opt-in, creates a run that probes every eligible listener", async () => {
    const fetchMock = installFetch(realisticBackend().handler);
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByText(/No runs yet/);
    await user.click(screen.getByRole("tab", { name: "TLS metadata scan" }));
    await user.click(screen.getByLabelText("Probe every eligible TLS listener on this machine"));
    await user.click(screen.getByRole("button", { name: "Run TLS metadata scan" }));
    expect(await screen.findByText(/Run #1 is queued/)).toBeTruthy();
    const post = fetchMock.mock.calls.find(([, i]) => i?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ type: "tls", config: {} });
    expect(within(rowFor(1)).getByText("TLS listeners on this machine")).toBeTruthy();
  });

  it("the filesystem scan still posts the same body as before, from the same page", async () => {
    const fetchMock = installFetch(realisticBackend().handler);
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByText(/No runs yet/);
    await user.type(screen.getByLabelText(/Folders to scan/), "C:\\certs");
    await user.click(screen.getByRole("button", { name: "Run filesystem scan" }));
    await screen.findByText(/Run #1 is queued/);
    const post = fetchMock.mock.calls.find(([, i]) => i?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ type: "filesystem", config: { roots: ["C:\\certs"] } });
  });

  it("lists TLS and filesystem runs together, and the Type filter separates them", async () => {
    installFetch(realisticBackend([makeRun({ run_number: 2, type: "tls", config: {}, record_count: 3, finding_count: 1 }), makeRun({ run_number: 1 })]).handler);
    const user = userEvent.setup();
    render(<RunsPage />);
    await screen.findByRole("table");
    expect(within(rowFor(2)).getByText("tls")).toBeTruthy();
    expect(within(rowFor(1)).getByText("filesystem")).toBeTruthy();
    await user.selectOptions(screen.getByLabelText(/Type/), "tls");
    await waitFor(() => expect(screen.queryByRole("row", { name: /^#1\b/ })).toBeNull());
    expect(rowFor(2)).toBeTruthy();
  });
});

describe("the notice about a newly created TLS run", () => {
  it("says no probe results, not no records, when a TLS run completes empty", () => {
    expect(createdNotice(4, makeRun({ run_number: 4, type: "tls", record_count: 0, finding_count: 0 })).text).toBe("Run #4 completed, but the agent reported no probe results.");
  });

  it("keeps the filesystem wording for filesystem runs", () => {
    expect(createdNotice(4, makeRun({ run_number: 4, record_count: 0, finding_count: 0 })).text).toBe("Run #4 completed, but the agent reported no records.");
  });

  it("is otherwise the same for both types", () => {
    for (const type of ["tls", "filesystem"]) {
      expect(createdNotice(4, makeRun({ run_number: 4, type, record_count: 2 })).text).toBe("Run #4 completed.");
      expect(createdNotice(4, queuedRun(4, { type })).text).toMatch(/queued/);
    }
  });
});

describe("the page intro", () => {
  it("no longer says that TLS runs need the API", async () => {
    installFetch(realisticBackend().handler);
    render(<RunsPage />);
    const intro = (await screen.findByRole("heading", { name: "Discovery runs" })).parentElement!.querySelector("p")!.textContent!;
    expect(intro).not.toMatch(/through the API/);
    expect(intro).toMatch(/TLS metadata scan/);
  });
});
