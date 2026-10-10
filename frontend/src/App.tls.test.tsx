import { cleanup, render, screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { installFetch, makeRun } from "./test/helpers";
import { reportBackend } from "./test/reportBackend";
import { makeProbe, makeTlsSummary } from "./test/tlsFixtures";

beforeEach(() => {
  window.location.hash = "";
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.location.hash = "";
});

function world() {
  const tls = makeRun({ run_number: 2, type: "tls", config: { ports: [8443] }, record_count: 1, finding_count: 1 });
  const fs = makeRun({ run_number: 1 });
  const be = reportBackend([tls, fs], { [tls.run_id]: { tlsSummary: makeTlsSummary(tls, {}, { probe_attempts: 1, handshakes_completed: 1 }), tlsObservations: [makeProbe(0)] } });
  const fetchMock = installFetch(be.handler);
  return { tls, fs, fetchMock };
}

describe("TLS reports in the application", () => {
  it("opens a TLS run's report from the list, and a filesystem run's report from the same list", async () => {
    const { tls, fs, fetchMock } = world();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("table");
    expect(screen.getByText("TLS listeners on this machine (ports 8443)")).toBeTruthy();         // the scope of a TLS run, not "Agent default locations"
    await user.click(screen.getByRole("link", { name: "Open TLS report for run 2" }));
    expect(await screen.findByRole("heading", { level: 1, name: /Run #2\s+TLS probe report/ })).toBeTruthy();
    expect(window.location.hash).toBe(`#/runs/${tls.run_id}`);
    await screen.findByRole("table", { name: /Active probe attempts/ });
    expect(fetchMock.mock.calls.map(([u]) => String(u)).filter((u) => u.includes(`/runs/${tls.run_id}/fs/`))).toEqual([]);

    await user.click(screen.getByRole("link", { name: "← Discovery runs" }));
    await waitFor(() => expect(window.location.hash).toBe("#/runs"));
    await user.click(screen.getByRole("link", { name: "Open report for run 1" }));
    expect(await screen.findByRole("heading", { level: 1, name: /Run #1\s+filesystem report/ })).toBeTruthy();
    expect(window.location.hash).toBe(`#/runs/${fs.run_id}`);
    expect(screen.queryByLabelText("How this TLS data was collected")).toBeNull();
  });

  it("loads a TLS report straight from its link, as after a browser refresh, and offers the way back", async () => {
    const { tls } = world();
    window.location.hash = `#/runs/${tls.run_id}`;
    render(<App />);
    expect(await screen.findByRole("heading", { level: 1, name: /Run #2\s+TLS probe report/ })).toBeTruthy();
    expect(await screen.findByRole("table", { name: /Active probe attempts/ })).toBeTruthy();
    expect(screen.getByLabelText("How this TLS data was collected")).toBeTruthy();
    const back = screen.getByRole("link", { name: "← Discovery runs" });
    expect(back.getAttribute("href")).toBe("#/runs");
    expect(within(screen.getByRole("main")).getByRole("status", { name: "Run outcome" })).toBeTruthy();
  });

  it("a second load of the same link shows the same report", async () => {
    const { tls } = world();
    window.location.hash = `#/runs/${tls.run_id}`;
    const first = render(<App />);
    await screen.findByRole("heading", { level: 1, name: /Run #2\s+TLS probe report/ });
    first.unmount();
    render(<App />);                                                                         // a fresh page load on the same URL
    expect(await screen.findByRole("heading", { level: 1, name: /Run #2\s+TLS probe report/ })).toBeTruthy();
    expect(await screen.findByRole("table", { name: /Active probe attempts/ })).toBeTruthy();
  });
});
