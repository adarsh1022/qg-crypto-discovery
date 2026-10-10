import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RunsPage } from "./RunsPage";
import { backend } from "../test/fakeBackend";
import { errorResponse, installFetch, jsonResponse, makeRun, queuedRun, runningRun } from "../test/helpers";

afterEach(() => {
  vi.unstubAllGlobals();
});

async function showPage() {
  const user = userEvent.setup();
  render(<RunsPage />);
  return user;
}

const rowFor = (n: number) => screen.getByRole("row", { name: new RegExp(`^#${n}\\b`) });

describe("listing", () => {
  it("shows a loading state, then every run with its real status and counts", async () => {
    const { handler } = backend([
      queuedRun(5),
      runningRun(4, { record_count: 3, finding_count: 2 }),
      makeRun({ run_number: 3 }),
      makeRun({ run_number: 2, status: "partial", stop_reason: "cancelled", record_count: 4, finding_count: 3 }),
      makeRun({ run_number: 1, status: "failed", stop_reason: "invalid_config", record_count: 0, finding_count: 0 }),
    ]);
    installFetch(handler);
    await showPage();
    expect(screen.getByText(/Loading runs/)).toBeTruthy();
    await screen.findByRole("table");

    expect(within(rowFor(5)).getByText("Queued")).toBeTruthy();
    expect(within(rowFor(4)).getByText("Running")).toBeTruthy();
    expect(within(rowFor(3)).getByText("Completed")).toBeTruthy();
    expect(within(rowFor(2)).getByText("Partial")).toBeTruthy();
    expect(within(rowFor(1)).getByText("Failed")).toBeTruthy();
    expect(within(rowFor(3)).getByText("Finished normally.")).toBeTruthy();
    expect(within(rowFor(2)).getByText("Cancelled.")).toBeTruthy();
    expect(within(rowFor(1)).getByText(/rejected the scan settings/)).toBeTruthy();
    const cells = within(rowFor(3)).getAllByRole("cell").map((c) => c.textContent);
    expect(cells).toContain("8");
    expect(cells).toContain("6");
  });

  it("does not present a queued run's zero counts as results", async () => {
    installFetch(backend([queuedRun(1)]).handler);
    await showPage();
    await screen.findByRole("table");
    const cells = within(rowFor(1)).getAllByRole("cell").map((c) => c.textContent);
    expect(cells.filter((t) => t === "0")).toHaveLength(0);
  });

  it("explains an empty list, and a filter that matches nothing", async () => {
    const fetchMock = installFetch(backend([]).handler);
    const user = await showPage();
    expect(await screen.findByText(/No runs yet/)).toBeTruthy();
    await user.selectOptions(screen.getByLabelText(/Status/), "failed");
    expect(await screen.findByText(/No runs match these filters/)).toBeTruthy();
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes("status=failed"))).toBe(true);
  });

  it("shows an error with a working Retry when the first load fails", async () => {
    let up = false;
    const { handler } = backend([makeRun({ run_number: 1 })]);
    installFetch((req) => (up ? handler(req) : errorResponse(503, "busy")));
    const user = await showPage();
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/busy/i);
    expect(screen.queryByRole("table")).toBeNull();
    up = true;
    await user.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("table")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("says the backend is unreachable, and how to start it", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("Failed to fetch"))));
    await showPage();
    expect((await screen.findByRole("alert")).textContent).toMatch(/Cannot reach the backend.*python -m backend/);
  });

  it("keeps the last good list, marked out of date, when a refresh fails", async () => {
    let up = true;
    const { handler } = backend([makeRun({ run_number: 1 })]);
    installFetch((req) => (up ? handler(req) : errorResponse(500, "internal_error")));
    const user = await showPage();
    await screen.findByRole("table");
    up = false;
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/may be out of date/);
    expect(screen.getByRole("table")).toBeTruthy();
    expect(rowFor(1)).toBeTruthy();
  });

  it("loads further pages by offset and never shows a run twice", async () => {
    const many = Array.from({ length: 60 }, (_, i) => makeRun({ run_number: 60 - i }));
    const fetchMock = installFetch(backend(many).handler);
    const user = await showPage();
    await screen.findByRole("table");
    expect(screen.getAllByRole("row")).toHaveLength(51); // header + 50
    await user.click(screen.getByRole("button", { name: "Load more" }));
    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(61));
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes("offset=50"))).toBe(true);
  });

  it("renders text from the backend as text, never as markup", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    installFetch(backend([makeRun({ run_number: 1, status: "failed", stop_reason: evil, config: { roots: [`C:\\<script>alert(1)</script>`] } })]).handler);
    await showPage();
    await screen.findByRole("table");
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
    expect(within(rowFor(1)).getByText(evil)).toBeTruthy();
  });

  it("shows an unrecognised status as Unknown", async () => {
    installFetch(backend([makeRun({ run_number: 1, status: "exploded" })]).handler);
    await showPage();
    await screen.findByRole("table");
    expect(within(rowFor(1)).getByText("Unknown")).toBeTruthy();
  });

  it("tells the user to start the agent when a run has been queued for a while", async () => {
    const old = new Date(Date.now() - 60_000).toISOString();
    installFetch(backend([queuedRun(1, { queued_at: old }), queuedRun(2, { queued_at: new Date().toISOString() })]).handler);
    await showPage();
    await screen.findByRole("table");
    expect(within(rowFor(1)).getByText(/Waiting for an agent/)).toBeTruthy();
    expect(within(rowFor(2)).queryByText(/Waiting for an agent/)).toBeNull();
  });
});

describe("cancelling", () => {
  it("offers Cancel only where it makes sense", async () => {
    installFetch(backend([
      queuedRun(6),
      runningRun(5),
      runningRun(4, { cancel_requested: true }),
      makeRun({ run_number: 3 }),
      makeRun({ run_number: 2, status: "partial" }),
      makeRun({ run_number: 1, status: "failed" }),
    ]).handler);
    await showPage();
    await screen.findByRole("table");
    expect(screen.queryByRole("button", { name: "Cancel run 6" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Cancel run 5" })).toBeTruthy();
    for (const n of [4, 3, 2, 1]) expect(screen.queryByRole("button", { name: `Cancel run ${n}` })).toBeNull();
    expect(within(rowFor(4)).getByText("Running (cancelling)")).toBeTruthy();
  });

  it("cancels a queued run and shows what the backend says it now is", async () => {
    const fetchMock = installFetch(backend([queuedRun(1)]).handler);
    const user = await showPage();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: "Cancel run 1" }));
    await waitFor(() => expect(within(rowFor(1)).getByText("Failed")).toBeTruthy());
    expect(within(rowFor(1)).getByText("Cancelled.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Cancel run 1" })).toBeNull();
    const post = fetchMock.mock.calls.find(([u, i]) => String(u).endsWith("/cancel") && i?.method === "POST");
    expect(String(post?.[0])).toBe(`/api/runs/${"1".padStart(32, "0")}/cancel`);
  });

  it("marks a running run as cancelling and drops the button", async () => {
    installFetch(backend([runningRun(1)]).handler);
    const user = await showPage();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: "Cancel run 1" }));
    await waitFor(() => expect(within(rowFor(1)).getByText("Running (cancelling)")).toBeTruthy());
    expect(screen.queryByRole("button", { name: "Cancel run 1" })).toBeNull();
  });

  it("explains a refused cancel and re-reads the run", async () => {
    const { handler, runs } = backend([runningRun(1)], { onCancel: () => errorResponse(409, "run_not_cancellable") });
    const fetchMock = installFetch(handler);
    const user = await showPage();
    await screen.findByRole("table");
    runs[0] = makeRun({ run_number: 1 }); // it finished while the user was looking
    await user.click(screen.getByRole("button", { name: "Cancel run 1" }));
    expect(await within(rowFor(1)).findByText(/already finished/)).toBeTruthy();
    await waitFor(() => expect(within(rowFor(1)).getByText("Completed")).toBeTruthy());
    expect(fetchMock.mock.calls.filter(([, i]) => (i?.method ?? "GET") === "GET").length).toBeGreaterThanOrEqual(2);
  });

  it("shows a network failure while cancelling and lets the user try again", async () => {
    let fail = true;
    const { handler } = backend([queuedRun(1)]);
    installFetch((req) => (fail && req.path.endsWith("/cancel") ? Promise.reject(new TypeError("down")) as never : handler(req)));
    const user = await showPage();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: "Cancel run 1" }));
    expect(await within(rowFor(1)).findByText(/Cannot reach the backend/)).toBeTruthy();
    fail = false;
    await user.click(screen.getByRole("button", { name: "Cancel run 1" }));
    await waitFor(() => expect(within(rowFor(1)).getByText("Failed")).toBeTruthy());
  });
});

describe("starting a scan", () => {
  it("refuses an empty form without contacting the backend", async () => {
    const fetchMock = installFetch(backend([]).handler);
    const user = await showPage();
    await screen.findByText(/No runs yet/);
    const before = fetchMock.mock.calls.length;
    await user.click(screen.getByRole("button", { name: "Run filesystem scan" }));
    expect((await screen.findByText(/at least one folder/i)).textContent).toBeTruthy();
    expect(screen.getByLabelText(/Folders to scan/).getAttribute("aria-invalid")).toBe("true");
    expect(fetchMock.mock.calls.length).toBe(before);
  });

  it("refuses a relative or network path", async () => {
    installFetch(backend([]).handler);
    const user = await showPage();
    await user.type(screen.getByLabelText(/Folders to scan/), "certs\\here");
    await user.click(screen.getByRole("button", { name: "Run filesystem scan" }));
    expect((await screen.findByText(/absolute local path/)).textContent).toBeTruthy();
  });

  it("creates a filesystem run with explicit folders and shows it as queued", async () => {
    const fetchMock = installFetch(backend([]).handler);
    const user = await showPage();
    await screen.findByText(/No runs yet/);
    await user.type(screen.getByLabelText(/Folders to scan/), "C:\\certs");
    await user.click(screen.getByText("Advanced options"));
    await user.type(screen.getByLabelText(/Maximum folder depth/), "4");
    await user.click(screen.getByRole("button", { name: "Run filesystem scan" }));

    expect(await screen.findByText(/Run #1 is queued/)).toBeTruthy();
    const post = fetchMock.mock.calls.find(([, i]) => i?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ type: "filesystem", config: { roots: ["C:\\certs"], max_depth: 4 } });
    expect(await screen.findByRole("table")).toBeTruthy();
    expect(within(rowFor(1)).getByText("Queued")).toBeTruthy();
    expect((screen.getByLabelText(/Folders to scan/) as HTMLTextAreaElement).value).toBe(""); // the form resets
  });

  it("scans the agent's default locations only when that is chosen explicitly", async () => {
    const fetchMock = installFetch(backend([]).handler);
    const user = await showPage();
    await screen.findByText(/No runs yet/);
    await user.click(screen.getByLabelText(/default locations/i));
    expect((screen.getByLabelText(/Folders to scan/) as HTMLTextAreaElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "Run filesystem scan" }));
    await screen.findByText(/Run #1 is queued/);
    const post = fetchMock.mock.calls.find(([, i]) => i?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ type: "filesystem", config: {} });
    expect(within(rowFor(1)).getByText("Agent default locations")).toBeTruthy();
  });

  it("shows the backend's objection next to the field it names", async () => {
    installFetch(backend([], { onCreate: () => errorResponse(422, "invalid_config", "The run configuration is not acceptable.", { field: "max_depth", problem: "wrong_type_or_range" }) }).handler);
    const user = await showPage();
    await user.type(screen.getByLabelText(/Folders to scan/), "C:\\certs");
    await user.click(screen.getByText("Advanced options"));
    await user.click(screen.getByRole("button", { name: "Run filesystem scan" }));
    const message = await screen.findByText("The backend did not accept this value.");
    expect(message.id).toBe("scan-depth-error");
    expect(screen.getByLabelText(/Maximum folder depth/).getAttribute("aria-invalid")).toBe("true");
    expect(screen.queryByText(/is queued/)).toBeNull();
  });

  it.each([
    [() => errorResponse(422, "invalid_config", "x", { problem: "unknown_key", allowed_keys: ["roots"] }), /did not accept the scan settings/],
    [() => errorResponse(503, "busy"), /busy/i],
    [() => errorResponse(403, "origin_not_allowed"), /127\.0\.0\.1 or localhost/],
    [() => errorResponse(500, "internal_error"), /internal error/],
  ])("shows a readable message when creating fails (%#)", async (make, expected) => {
    installFetch(backend([], { onCreate: make }).handler);
    const user = await showPage();
    await user.type(screen.getByLabelText(/Folders to scan/), "C:\\certs");
    await user.click(screen.getByRole("button", { name: "Run filesystem scan" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(expected);
    expect((screen.getByLabelText(/Folders to scan/) as HTMLTextAreaElement).value).toBe("C:\\certs"); // nothing the user typed is lost
  });

  it("cannot be submitted twice while the request is in flight", async () => {
    let release: (r: Response) => void = () => {};
    const { handler, runs } = backend([]);
    const fetchMock = installFetch((req) => (req.method === "POST" ? new Promise<Response>((r) => (release = r)) : handler(req)));
    const user = await showPage();
    await user.type(screen.getByLabelText(/Folders to scan/), "C:\\certs");
    await user.click(screen.getByRole("button", { name: "Run filesystem scan" }));
    const busy = await screen.findByRole("button", { name: /Starting/ });
    expect((busy as HTMLButtonElement).disabled).toBe(true);
    await user.click(busy);
    expect(fetchMock.mock.calls.filter(([, i]) => i?.method === "POST")).toHaveLength(1);
    runs.unshift(queuedRun(1)); // the backend now has the run, as it would after a real create
    release(jsonResponse({ run: queuedRun(1) }, 201));
    await screen.findByText(/Run #1 is queued/);
  });
});

describe("what the page says about itself", () => {
  it("says both scan types start here, that TLS scans are active probes, and that relationship mapping is not built", async () => {
    installFetch(backend([]).handler);
    await showPage();
    const intro = (await screen.findByRole("heading", { name: "Discovery runs" })).parentElement!.querySelector("p")!.textContent!;
    expect(intro).toMatch(/Start a filesystem scan or a TLS metadata scan below/);
    expect(intro).toMatch(/active probes .* not traffic capture/);
    expect(intro).toMatch(/Relationship mapping is not implemented yet/);
    expect(intro).not.toMatch(/created through the API|not available/i);
  });
});

describe("the findings column is named for what each run type counts", () => {
  const tlsRow = (over = {}) => makeRun({ run_number: 7, type: "tls", config: {}, record_count: 5, finding_count: 2, ...over });

  it("keeps 'Sightings' and its filesystem tooltip in the header", async () => {
    installFetch(backend([makeRun({ run_number: 1 })]).handler);
    await showPage();
    const header = await screen.findByRole("columnheader", { name: "Sightings" });
    expect(header.getAttribute("title")).toBe("Records that carry a certificate (one certificate seen in several files counts once per file)");
  });

  it("labels a TLS row's number as completed handshakes, with the same value, and leaves filesystem rows alone", async () => {
    installFetch(backend([tlsRow(), makeRun({ run_number: 1, record_count: 8, finding_count: 6 })]).handler);
    await showPage();
    await screen.findByRole("table");
    const tls = within(rowFor(7));
    expect(tls.getByText("completed handshakes")).toBeTruthy();
    const cell = tls.getByText("completed handshakes").closest("td")!;
    expect(cell.textContent).toBe("2completed handshakes");                       // the metric itself is unchanged: finding_count
    expect(cell.getAttribute("title")).toMatch(/Completed TLS handshakes.*not a count of sightings/);
    const fs = within(rowFor(1));
    expect(fs.queryByText(/handshake/)).toBeNull();
    expect(fs.getAllByRole("cell").map((c) => c.textContent)).toContain("6");
    expect(fs.getAllByRole("cell").every((c) => !c.getAttribute("title")?.includes("handshake"))).toBe(true);
  });

  it("shows a dash, not a caption, for a TLS run that has not started", async () => {
    installFetch(backend([tlsRow({ status: "queued", started_at: null, finished_at: null, duration_ms: null, record_count: 0, finding_count: 0, stop_reason: null })]).handler);
    await showPage();
    await screen.findByRole("table");
    expect(within(rowFor(7)).queryByText(/handshake/)).toBeNull();
  });
});
