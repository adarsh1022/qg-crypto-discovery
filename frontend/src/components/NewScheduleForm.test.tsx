import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { errorResponse, installFetch, jsonResponse } from "../test/helpers";
import { makeSchedule, schedulesBackend } from "../test/scheduleHelpers";
import { NewScheduleForm } from "./NewScheduleForm";
import { SchedulesPanel } from "./SchedulesPanel";

afterEach(() => {
  vi.unstubAllGlobals();
});

function setup(hooks = {}) {
  const fake = schedulesBackend([], hooks);
  installFetch((req) => fake.handler(req) ?? errorResponse(404, "not_found"));
  const onCreated = vi.fn();
  const user = userEvent.setup();
  render(<NewScheduleForm onCreated={onCreated} />);
  return { ...fake, onCreated, user };
}
const amount = () => screen.getByLabelText("Run every") as HTMLInputElement;
const create = () => screen.getByRole("button", { name: "Create schedule" });

describe("the interval", () => {
  it("refuses an empty or out-of-range interval next to the field, and sends nothing", async () => {
    const { user, created } = setup();
    await user.type(screen.getByLabelText(/Folders for this schedule/), "C:\\certs");
    await user.click(create());
    expect((await screen.findByRole("alert")).textContent).toMatch(/from 15 seconds to 7 days/);
    expect(amount().getAttribute("aria-invalid")).toBe("true");
    await user.type(amount(), "10");
    await user.selectOptions(screen.getByLabelText("Interval unit"), "seconds");
    await user.click(create());
    expect(created).toHaveLength(0);
  });

  it.each([["15", "seconds", 15], ["2", "minutes", 120], ["1", "hours", 3600], ["7", "days", 604_800], ["30", "seconds", 30]])(
    "%s %s becomes %d seconds in the request",
    async (n, unit, seconds) => {
      const { user, created } = setup();
      await user.type(screen.getByLabelText(/Folders for this schedule/), "C:\\certs");
      await user.type(amount(), n);
      await user.selectOptions(screen.getByLabelText("Interval unit"), unit);
      await user.click(create());
      await waitFor(() => expect(created).toHaveLength(1));
      expect(created[0]).toEqual({ run_type: "filesystem", interval_seconds: seconds, config: { roots: ["C:\\certs"] } });
    },
  );

  it.each([["14", "seconds"], ["8", "days"], ["1.5", "minutes"], ["abc", "minutes"], ["0", "hours"]])("refuses %s %s", async (n, unit) => {
    const { user, created } = setup();
    await user.type(screen.getByLabelText(/Folders for this schedule/), "C:\\certs");
    await user.type(amount(), n);
    await user.selectOptions(screen.getByLabelText("Interval unit"), unit);
    await user.click(create());
    expect(await screen.findByText(/from 15 seconds to 7 days/)).toBeTruthy();
    expect(created).toHaveLength(0);
  });
});

describe("a filesystem schedule", () => {
  it("needs folders or the explicit choice of the standard folders", async () => {
    const { user, created } = setup();
    await user.type(amount(), "5");
    await user.click(create());
    expect((await screen.findByText(/at least one folder/i)).textContent).toBeTruthy();
    expect(created).toHaveLength(0);
    await user.click(screen.getByLabelText(/standard folders/));
    expect((screen.getByLabelText(/Folders for this schedule/) as HTMLTextAreaElement).disabled).toBe(true);
    await user.click(create());
    await waitFor(() => expect(created).toHaveLength(1));
    expect(created[0]).toEqual({ run_type: "filesystem", interval_seconds: 300, config: {} });
  });

  it("refuses a relative path", async () => {
    const { user, created } = setup();
    await user.type(amount(), "5");
    await user.type(screen.getByLabelText(/Folders for this schedule/), "certs\\here");
    await user.click(create());
    expect((await screen.findByText(/absolute local path/)).textContent).toBeTruthy();
    expect(created).toHaveLength(0);
  });

  it("never sends the TLS opt-in", async () => {
    const { user, created } = setup();
    await user.type(amount(), "5");
    await user.type(screen.getByLabelText(/Folders for this schedule/), "C:\\certs");
    await user.click(create());
    await waitFor(() => expect(created).toHaveLength(1));
    expect("probe_all_listeners" in created[0]).toBe(false);
  });
});

describe("a TLS schedule", () => {
  async function pickTls(user: ReturnType<typeof userEvent.setup>) {
    await user.selectOptions(screen.getByLabelText("Kind of scan"), "tls");
    await user.type(amount(), "5");
  }

  it("explains what is probed and offers no field for a host or address", async () => {
    const { user } = setup();
    await pickTls(user);
    expect(document.body.textContent).toMatch(/active probe, not traffic capture/);
    expect(document.body.textContent).toMatch(/cannot\s+be pointed at another host/);
    const labels = Array.from(document.querySelectorAll("label")).map((l) => l.textContent ?? "");
    expect(labels.some((l) => /host|address|\bip\b|url/i.test(l))).toBe(false);
  });

  it("with no ports and no opt-in: refuses, and sends nothing (the backend would refuse it as well)", async () => {
    const { user, created } = setup();
    await pickTls(user);
    await user.click(create());
    expect((await screen.findByText(/at least one port, or tick the box/)).textContent).toBeTruthy();
    expect(created).toHaveLength(0);
  });

  it("with ports: sends them and no opt-in", async () => {
    const { user, created } = setup();
    await pickTls(user);
    await user.type(screen.getByLabelText("Ports for this schedule"), "8443, 9443");
    await user.click(create());
    await waitFor(() => expect(created).toHaveLength(1));
    expect(created[0]).toEqual({ run_type: "tls", interval_seconds: 300, config: { ports: [8443, 9443] } });
  });

  it("with the explicit opt-in: sends it, labelled as broad, and no ports", async () => {
    const { user, created } = setup();
    await pickTls(user);
    expect(document.body.textContent).toMatch(/non-TLS services may log each attempt/);
    await user.type(screen.getByLabelText("Ports for this schedule"), "443");
    await user.click(screen.getByLabelText("Probe all eligible TLS listeners every time (broad)"));
    expect((screen.getByLabelText("Ports for this schedule") as HTMLInputElement).disabled).toBe(true);
    await user.click(create());
    await waitFor(() => expect(created).toHaveLength(1));
    expect(created[0]).toEqual({ run_type: "tls", interval_seconds: 300, config: {}, probe_all_listeners: true });
  });

  it("keeps what was typed for either type when the user switches back and forth", async () => {
    const { user } = setup();
    await user.type(screen.getByLabelText(/Folders for this schedule/), "C:\\certs");
    await user.selectOptions(screen.getByLabelText("Kind of scan"), "tls");
    await user.type(screen.getByLabelText("Ports for this schedule"), "8443");
    await user.selectOptions(screen.getByLabelText("Kind of scan"), "filesystem");
    expect((screen.getByLabelText(/Folders for this schedule/) as HTMLTextAreaElement).value).toBe("C:\\certs");
    await user.selectOptions(screen.getByLabelText("Kind of scan"), "tls");
    expect((screen.getByLabelText("Ports for this schedule") as HTMLInputElement).value).toBe("8443");
  });
});

describe("creating", () => {
  it("hands the created schedule to the page, once, and clears the form", async () => {
    const { user, onCreated, created } = setup();
    await user.type(amount(), "5");
    await user.type(screen.getByLabelText(/Folders for this schedule/), "C:\\certs");
    await user.click(create());
    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1));
    expect(created).toHaveLength(1);
    expect(onCreated.mock.calls[0][0]).toMatchObject({ run_type: "filesystem", interval_seconds: 300, enabled: true, state: "waiting" });
    expect(amount().value).toBe("");
    expect((screen.getByLabelText(/Folders for this schedule/) as HTMLTextAreaElement).value).toBe("");
  });

  it("cannot be submitted twice while the request is in flight", async () => {
    let release: (r: Response) => void = () => {};
    const fake = schedulesBackend([]);
    installFetch((req) => (req.method === "POST" ? new Promise<Response>((r) => (release = r)) : (fake.handler(req) ?? errorResponse(404, "not_found"))));
    const onCreated = vi.fn();
    const user = userEvent.setup();
    render(<NewScheduleForm onCreated={onCreated} />);
    await user.type(amount(), "5");
    await user.type(screen.getByLabelText(/Folders for this schedule/), "C:\\certs");
    await user.click(create());
    const busy = await screen.findByRole("button", { name: /Creating/ });
    expect((busy as HTMLButtonElement).disabled).toBe(true);
    await user.click(busy);
    release(jsonResponse({ schedule: makeSchedule() }, 201));
    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1));
    expect(fake.created).toHaveLength(0);                                    // the stalled POST never reached the fake's list
  });

  it("shows the backend's objection at the field it named and keeps what was typed", async () => {
    const { user, onCreated } = setup({ onCreate: () => errorResponse(422, "invalid_schedule", "x", { field: "interval_seconds", problem: "out_of_range" }) });
    await user.type(amount(), "5");
    await user.type(screen.getByLabelText(/Folders for this schedule/), "C:\\certs");
    await user.click(create());
    expect((await screen.findByText("The backend did not accept this interval.")).id).toBe("schedule-interval-error");
    expect(amount().value).toBe("5");
    expect(onCreated).not.toHaveBeenCalled();
  });

  it("explains the TLS opt-in when the backend insists on it", async () => {
    const { user } = setup({ onCreate: () => errorResponse(422, "invalid_schedule", "x", { field: "probe_all_listeners", problem: "required_without_ports" }) });
    await user.selectOptions(screen.getByLabelText("Kind of scan"), "tls");
    await user.type(amount(), "5");
    await user.type(screen.getByLabelText("Ports for this schedule"), "443");
    await user.click(create());
    expect((await screen.findByText(/needs ports or the explicit opt-in/)).textContent).toBeTruthy();
  });

  it.each([
    [() => errorResponse(409, "too_many_schedules", "x", { max_schedules: 50 }), /maximum number of schedules/],
    [() => errorResponse(503, "busy"), /busy/i],
    [() => errorResponse(403, "origin_not_allowed"), /127\.0\.0\.1 or localhost/],
    [() => errorResponse(500, "internal_error"), /internal error/],
  ])("shows a readable message when creating fails (%#)", async (make, expected) => {
    const { user } = setup({ onCreate: make });
    await user.type(amount(), "5");
    await user.type(screen.getByLabelText(/Folders for this schedule/), "C:\\certs");
    await user.click(create());
    expect((await screen.findByRole("alert")).textContent).toMatch(expected);
    expect((screen.getByLabelText(/Folders for this schedule/) as HTMLTextAreaElement).value).toBe("C:\\certs");
  });
});

describe("inside the panel", () => {
  it("a created schedule appears in the list with the backend's own id and first due time, and a notice says so", async () => {
    const fake = schedulesBackend([]);
    installFetch((req) => fake.handler(req) ?? errorResponse(404, "not_found"));
    const user = userEvent.setup();
    render(<SchedulesPanel />);
    await screen.findByText(/No schedules yet/);
    await user.click(screen.getByText("New schedule"));
    await user.type(screen.getByLabelText("Run every"), "10");
    await user.type(screen.getByLabelText(/Folders for this schedule/), "C:\\certs");
    await user.click(screen.getByRole("button", { name: "Create schedule" }));
    expect(await screen.findByRole("listitem", { name: /Schedule sched-/ })).toBeTruthy();
    expect(screen.getByText(/Schedule sched-\w+ created\. Its first run is due .*2026/)).toBeTruthy();
    expect(screen.queryByText(/No schedules yet/)).toBeNull();
    expect((screen.getByText("New schedule").closest("details") as HTMLDetailsElement).open).toBe(false);
  });
});
