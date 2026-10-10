import { describe, expect, it } from "vitest";
import { buildTlsConfig, EMPTY_TLS_FORM, type TlsFormValues } from "./scanForm";

const form = (over: Partial<TlsFormValues> = {}): TlsFormValues => ({ ...EMPTY_TLS_FORM, ...over });

describe("buildTlsConfig: no silent broad scan", () => {
  it("refuses an empty form: no ports and no explicit opt-in", () => {
    const result = buildTlsConfig(form());
    expect(result.config).toBeNull();
    expect(result.errors.ports).toMatch(/at least one port, or tick the box/);
  });

  it("refuses ports that are only whitespace or separators", () => {
    expect(buildTlsConfig(form({ ports: " ,; \n" })).config).toBeNull();
  });

  it("the explicit opt-in is the only way to get a configuration without ports, and it sends no ports key at all", () => {
    const result = buildTlsConfig(form({ probeAll: true }));
    expect(result.config).toEqual({});
    expect("ports" in (result.config ?? {})).toBe(false);
  });

  it("with the opt-in, a port list that was typed earlier is ignored, not sent", () => {
    expect(buildTlsConfig(form({ probeAll: true, ports: "443, 8443" })).config).toEqual({});
  });

  it("with the opt-in, an invalid leftover port list does not block the scan", () => {
    expect(buildTlsConfig(form({ probeAll: true, ports: "not a port" })).config).toEqual({});
  });
});

describe("buildTlsConfig: ports", () => {
  it.each([
    ["443", [443]],
    ["443 8443", [443, 8443]],
    ["443,8443", [443, 8443]],
    ["443; 8443 ,9443", [443, 8443, 9443]],
    ["  443\n8443\r\n", [443, 8443]],
    ["443 443 8443 443", [443, 8443]],
    ["1 65535", [1, 65535]],
    ["0080", [80]],
  ])("reads %j as %j", (text, expected) => {
    expect(buildTlsConfig(form({ ports: text })).config).toEqual({ ports: expected });
  });

  it.each(["0", "65536", "-1", "80-90", "http", "443 http", "1e3", "4.5", "443:8443", "999999", "8080abc", "٤٤٣"])("refuses %j", (text) => {
    const result = buildTlsConfig(form({ ports: text }));
    expect(result.config).toBeNull();
    expect(result.errors.ports).toMatch(/whole numbers from 1 to 65535/);
  });

  it("allows 256 different ports and refuses 257", () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => i + 1).join(" ");
    expect(buildTlsConfig(form({ ports: many(256) })).config?.ports).toHaveLength(256);
    const over = buildTlsConfig(form({ ports: many(257) }));
    expect(over.config).toBeNull();
    expect(over.errors.ports).toMatch(/At most 256/);
  });

  it("counts the limit after removing duplicates", () => {
    const text = Array.from({ length: 400 }, (_, i) => (i % 256) + 1).join(" ");
    expect(buildTlsConfig(form({ ports: text })).config?.ports).toHaveLength(256);
  });
});

describe("buildTlsConfig: advanced limits are the backend's", () => {
  const ok = (over: Partial<TlsFormValues>) => buildTlsConfig(form({ ports: "443", ...over }));

  it("leaves empty advanced fields out of the configuration", () => {
    expect(ok({}).config).toEqual({ ports: [443] });
  });

  it("sends the values it was given", () => {
    expect(ok({ maxTargets: "50", connectTimeoutSeconds: "1.5", handshakeTimeoutSeconds: "5", timeBudgetSeconds: "120" }).config).toEqual({
      ports: [443], max_targets: 50, connect_timeout_seconds: 1.5, handshake_timeout_seconds: 5, time_budget_seconds: 120,
    });
  });

  it.each([["1", true], ["1024", true], ["0", false], ["1025", false], ["12.5", false], ["abc", false], ["-3", false], ["1e3", false]])(
    "maximum targets %j is %s",
    (text, valid) => {
      const result = ok({ maxTargets: text });
      expect(result.config !== null).toBe(valid);
      if (!valid) expect(result.errors.max_targets).toMatch(/1 to 1024/);
    },
  );

  it.each([["0.1", true], ["30", true], ["30.0", true], ["0", false], ["30.1", false], ["31", false], ["abc", false], ["-1", false], ["1e1", false]])(
    "a timeout of %j seconds is %s",
    (text, valid) => {
      for (const key of ["connectTimeoutSeconds", "handshakeTimeoutSeconds"] as const) {
        const result = ok({ [key]: text });
        expect(result.config !== null).toBe(valid);
        if (!valid) expect(Object.values(result.errors).join(" ")).toMatch(/above 0 and at most 30/);
      }
    },
  );

  it.each([["3600", true], ["0.5", true], ["3600.5", false], ["3601", false], ["0", false]])("a time budget of %j seconds is %s", (text, valid) => {
    const result = ok({ timeBudgetSeconds: text });
    expect(result.config !== null).toBe(valid);
    if (!valid) expect(result.errors.time_budget_seconds).toMatch(/at most 3600/);
  });

  it("reports every problem at once, each against the backend's own field name", () => {
    const result = buildTlsConfig(form({ ports: "x", maxTargets: "0", connectTimeoutSeconds: "99", handshakeTimeoutSeconds: "0", timeBudgetSeconds: "9999" }));
    expect(result.config).toBeNull();
    expect(Object.keys(result.errors).sort()).toEqual(["connect_timeout_seconds", "handshake_timeout_seconds", "max_targets", "ports", "time_budget_seconds"]);
  });

  it("can never produce a key the backend does not accept, and never a host or address", () => {
    const allowed = new Set(["ports", "max_targets", "connect_timeout_seconds", "handshake_timeout_seconds", "time_budget_seconds"]);
    const config = buildTlsConfig(form({ ports: "443", maxTargets: "5", connectTimeoutSeconds: "1", handshakeTimeoutSeconds: "1", timeBudgetSeconds: "1" })).config!;
    expect(Object.keys(config).every((k) => allowed.has(k))).toBe(true);
    expect(JSON.stringify(config)).not.toMatch(/host|addr|ip|target_/i);
  });
});
