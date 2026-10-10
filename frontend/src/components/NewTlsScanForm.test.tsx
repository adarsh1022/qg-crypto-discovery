import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { backend } from "../test/fakeBackend";
import { errorResponse, installFetch, jsonResponse, queuedRun } from "../test/helpers";
import { NewTlsScanForm } from "./NewTlsScanForm";

afterEach(() => {
  vi.unstubAllGlobals();
});

const createdAsRequested = (body: any) => jsonResponse({ run: queuedRun(1, { type: body.type, config: body.config }) }, 201);

function setup(handlerArg = backend([], { onCreate: createdAsRequested }).handler) {
  const fetchMock = installFetch(handlerArg);
  const onCreated = vi.fn();
  const user = userEvent.setup();
  render(<NewTlsScanForm onCreated={onCreated} />);
  const posts = () => fetchMock.mock.calls.filter(([, i]) => i?.method === "POST").map(([, i]) => JSON.parse(String(i?.body)));
  return { user, onCreated, posts, fetchMock };
}
const run = () => screen.getByRole("button", { name: "Run TLS metadata scan" });
const portsBox = () => screen.getByLabelText("Ports to probe") as HTMLInputElement;
const optIn = () => screen.getByLabelText("Probe every eligible TLS listener on this machine") as HTMLInputElement;

describe("what the form says", () => {
  it("states that this is an active probe and not traffic capture, and that targets come from this machine only", () => {
    setup();
    const text = document.body.textContent ?? "";
    expect(text).toMatch(/active probe, not traffic capture/);
    expect(text).toMatch(/no application data/);
    expect(text).toMatch(/Direction is unknown and packet counts are unavailable/);
    expect(text).toMatch(/cannot\s+be pointed at another host/);
    expect(text).toMatch(/list of listening sockets on this machine/);
  });

  it("explains that a port nothing listens on is ignored", () => {
    setup();
    expect(document.body.textContent).toMatch(/a port nothing listens on is ignored/);
  });

  it("has no field in which a host, address or URL could be entered", () => {
    setup();
    const labels = Array.from(document.querySelectorAll("label")).map((l) => l.textContent ?? "");
    expect(labels.some((l) => /host|address|\bip\b|url|target (host|address)/i.test(l))).toBe(false);
    const inputs = Array.from(document.querySelectorAll("input")).filter((i) => i.type !== "checkbox");
    expect(inputs.map((i) => i.id).sort()).toEqual(["tls-budget", "tls-connect", "tls-handshake", "tls-ports", "tls-targets"]);
  });

  it("marks the broad option as broad and keeps it unticked by default", () => {
    setup();
    expect(optIn().checked).toBe(false);
    expect(document.body.textContent).toMatch(/Broad: probes every listening TCP socket/);
  });
});

describe("no silent broad scan", () => {
  it("refuses an empty form without contacting the backend", async () => {
    const { user, posts, fetchMock } = setup();
    const before = fetchMock.mock.calls.length;
    await user.click(run());
    expect((await screen.findByText(/at least one port, or tick the box/)).textContent).toBeTruthy();
    expect(portsBox().getAttribute("aria-invalid")).toBe("true");
    expect(posts()).toHaveLength(0);
    expect(fetchMock.mock.calls.length).toBe(before);
  });

  it("probes every eligible listener only after the explicit opt-in, and then sends no ports", async () => {
    const { user, posts, onCreated } = setup();
    await user.click(optIn());
    expect(portsBox().disabled).toBe(true);
    await user.click(run());
    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1));
    expect(posts()).toEqual([{ type: "tls", config: {} }]);
  });

  it("ticking the opt-in disables the ports field without discarding what was typed, and unticking restores it", async () => {
    const { user, posts, onCreated } = setup();
    await user.type(portsBox(), "8443");
    await user.click(optIn());
    expect(portsBox().disabled).toBe(true);
    expect(portsBox().value).toBe("8443");
    await user.click(optIn());
    expect(portsBox().disabled).toBe(false);
    await user.click(run());
    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1));
    expect(posts()).toEqual([{ type: "tls", config: { ports: [8443] } }]);
  });
});

describe("starting a scan", () => {
  it("posts exactly the ports that were entered, once, and hands the new run to the page", async () => {
    const { user, posts, onCreated } = setup();
    await user.type(portsBox(), "8443, 9443 8443");
    await user.click(run());
    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1));
    expect(posts()).toEqual([{ type: "tls", config: { ports: [8443, 9443] } }]);
    expect(onCreated.mock.calls[0][0]).toMatchObject({ type: "tls", status: "queued", config: { ports: [8443, 9443] } }); // the run the backend returned
    expect(portsBox().value).toBe(""); // the form resets
  });

  it("sends the advanced limits it was given, under the backend's own names", async () => {
    const { user, posts, onCreated } = setup();
    await user.type(portsBox(), "443");
    await user.click(screen.getByText("Advanced TLS options"));
    await user.type(screen.getByLabelText("Maximum targets"), "10");
    await user.type(screen.getByLabelText("Connect timeout (seconds)"), "1.5");
    await user.type(screen.getByLabelText("Handshake timeout (seconds)"), "4");
    await user.type(screen.getByLabelText("Time budget (seconds)"), "90");
    await user.click(run());
    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1));
    expect(posts()).toEqual([{ type: "tls", config: { ports: [443], max_targets: 10, connect_timeout_seconds: 1.5, handshake_timeout_seconds: 4, time_budget_seconds: 90 } }]);
  });

  it("refuses bad advanced values next to their fields and sends nothing", async () => {
    const { user, posts } = setup();
    await user.type(portsBox(), "443");
    await user.click(screen.getByText("Advanced TLS options"));
    await user.type(screen.getByLabelText("Maximum targets"), "5000");
    await user.type(screen.getByLabelText("Time budget (seconds)"), "0");
    await user.click(run());
    expect((await screen.findByText(/whole number from 1 to 1024/)).id).toBe("tls-targets-error");
    expect(screen.getByText(/at most 3600\./, { selector: ".field-error" }).id).toBe("tls-budget-error");
    expect(posts()).toHaveLength(0);
  });

  it("cannot be submitted twice while the request is in flight", async () => {
    let release: (r: Response) => void = () => {};
    const fake = backend([]);
    const { user, posts, onCreated } = setup(((req: any) => (req.method === "POST" ? new Promise<Response>((r) => (release = r)) : fake.handler(req))) as any);
    await user.type(portsBox(), "443");
    await user.click(run());
    const busy = await screen.findByRole("button", { name: /Starting/ });
    expect((busy as HTMLButtonElement).disabled).toBe(true);
    expect(portsBox().disabled).toBe(true);
    await user.click(busy);
    expect(posts()).toHaveLength(1);
    release(jsonResponse({ run: queuedRun(1) }, 201));
    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1));
    expect(posts()).toHaveLength(1);
  });
});

describe("when the backend refuses", () => {
  it("shows its objection next to the field it names and keeps what was typed", async () => {
    const { user, onCreated } = setup(backend([], { onCreate: () => errorResponse(422, "invalid_config", "x", { field: "ports", problem: "wrong_type_or_range" }) }).handler);
    await user.type(portsBox(), "443");
    await user.click(run());
    const message = await screen.findByText("The backend did not accept this value.");
    expect(message.id).toBe("tls-ports-error");
    expect(portsBox().getAttribute("aria-invalid")).toBe("true");
    expect(portsBox().value).toBe("443");
    expect(onCreated).not.toHaveBeenCalled();
  });

  it.each([
    [() => errorResponse(422, "invalid_config", "x", { problem: "unknown_key", allowed_keys: ["ports"] }), /did not accept the scan settings/],
    [() => errorResponse(503, "busy"), /busy/i],
    [() => errorResponse(403, "origin_not_allowed"), /127\.0\.0\.1 or localhost/],
    [() => errorResponse(500, "internal_error"), /internal error/],
  ])("shows a readable message and loses nothing (%#)", async (make, expected) => {
    const { user, onCreated } = setup(backend([], { onCreate: make }).handler);
    await user.type(portsBox(), "443");
    await user.click(run());
    expect((await screen.findByRole("alert")).textContent).toMatch(expected);
    expect(portsBox().value).toBe("443");
    expect(onCreated).not.toHaveBeenCalled();
    expect(run().hasAttribute("disabled")).toBe(false); // the user can try again
  });
});
