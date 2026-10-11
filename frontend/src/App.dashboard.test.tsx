import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { dashboardBackend, makeDashboard, makeStats } from "./test/dashboardFixtures";
import { backend } from "./test/fakeBackend";
import { errorResponse, installFetch, makeRun } from "./test/helpers";

beforeEach(() => {
  window.location.hash = "";
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.location.hash = "";
});

function setup() {
  const runsApi = backend([makeRun({ run_number: 1 })]);
  const dash = dashboardBackend({ stats: makeStats([{ type: "filesystem", status: "completed", count: 1 }]), dashboard: makeDashboard(makeRun({ run_number: 1 })), tlsRuns: [] });
  const fetchMock = installFetch((req) => dash.handler(req) ?? runsApi.handler(req) ?? errorResponse(404, "not_found"));
  return { fetchMock, user: userEvent.setup() };
}
const nav = () => within(screen.getByRole("navigation", { name: "Main" }));

describe("the Dashboard in the app", () => {
  it("is in the main navigation, and the runs list is still the start page", async () => {
    setup();
    render(<App />);
    expect(nav().getByRole("link", { name: "Discovery runs" }).getAttribute("aria-current")).toBe("page");
    expect(nav().getByRole("link", { name: "Dashboard" }).getAttribute("href")).toBe("#/dashboard");
    expect(nav().getByRole("link", { name: "Dashboard" }).getAttribute("aria-current")).toBeNull();
    expect(screen.queryByRole("heading", { level: 1, name: "Dashboard" })).toBeNull();
  });

  it("opens from its link, marks itself current, and asks for dashboard data only then", async () => {
    const { fetchMock, user } = setup();
    render(<App />);
    expect(fetchMock.mock.calls.some(([u]) => String(u) === "/api/dashboard")).toBe(false);
    await user.click(nav().getByRole("link", { name: "Dashboard" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Dashboard" })).toBeTruthy();
    expect(nav().getByRole("link", { name: "Dashboard" }).getAttribute("aria-current")).toBe("page");
    expect(nav().getByRole("link", { name: "Discovery runs" }).getAttribute("aria-current")).toBeNull();
    expect(await screen.findByRole("figure", { name: "Runs by status and type" })).toBeTruthy();
    expect(fetchMock.mock.calls.some(([u]) => String(u) === "/api/dashboard")).toBe(true);
  });

  it("loads straight from #/dashboard, and the runs list is hidden behind it", async () => {
    setup();
    window.location.hash = "#/dashboard";
    render(<App />);
    expect(await screen.findByRole("heading", { level: 1, name: "Dashboard" })).toBeTruthy();
    expect(screen.queryByRole("heading", { level: 1, name: "Discovery runs" })).toBeNull();      // hidden, so not exposed
  });

  it("brings the user back to the runs list from the navigation", async () => {
    const { user } = setup();
    window.location.hash = "#/dashboard";
    render(<App />);
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    await user.click(nav().getByRole("link", { name: "Discovery runs" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Discovery runs" })).toBeTruthy();
    expect(screen.queryByRole("heading", { level: 1, name: "Dashboard" })).toBeNull();
  });
});
