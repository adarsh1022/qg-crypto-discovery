import { describe, expect, it } from "vitest";
import { attributionLabel, describeRunScope, explainToken, isTlsFinding, outcomeLabel, probeWarnings, warningLabel } from "./format";
import { makeRun } from "./test/helpers";

describe("TLS outcomes", () => {
  it("only a completed handshake is a TLS finding", () => {
    expect(isTlsFinding("completed")).toBe(true);
    for (const outcome of ["failed", "alert", "incomplete", "unknown", "", "anything"]) expect(isTlsFinding(outcome)).toBe(false);
  });

  it("labels every outcome, and shows an unknown one as text", () => {
    expect(outcomeLabel("completed")).toBe("TLS handshake completed");
    expect(outcomeLabel("failed")).toBe("Handshake failed");
    expect(outcomeLabel("alert")).toBe("TLS alert received");
    expect(outcomeLabel("incomplete")).toBe("Probe incomplete");
    expect(outcomeLabel("unknown")).toBe("Result unknown");
    expect(outcomeLabel("<b>x</b>")).toBe("<b>x</b>");
  });

  it("never describes a non-TLS service as TLS in an outcome label", () => {
    for (const outcome of ["failed", "alert", "incomplete", "unknown"]) expect(outcomeLabel(outcome)).not.toMatch(/completed|success|secure|valid/i);
  });
});

describe("TLS warnings and attribution", () => {
  it("explains the probe warning codes in words, and shows an unknown code as text", () => {
    expect(warningLabel("chain_unavailable")).toMatch(/Only the leaf certificate/);
    expect(warningLabel("connect_timeout")).toBe("The connection attempt timed out");
    expect(warningLabel("handshake_failed")).toMatch(/may not speak TLS/);
    expect(warningLabel("tlsv1_alert_protocol_version")).toBe("The service answered with a TLS alert (tlsv1_alert_protocol_version)");
    expect(warningLabel("something_new")).toBe("something_new");
    expect(warningLabel("pkcs12_integrity_not_verified")).toMatch(/PKCS#12/);                       // filesystem wording is unchanged
  });

  it("the two constant method markers are explained once, not on every row", () => {
    expect(probeWarnings(["active_probe", "packet_counts_unavailable", "connect_timeout"])).toEqual(["connect_timeout"]);
    expect(probeWarnings(["active_probe", "packet_counts_unavailable"])).toEqual([]);
    expect(warningLabel("active_probe")).toMatch(/not observed traffic/);
    expect(warningLabel("packet_counts_unavailable")).toMatch(/unavailable/);
  });

  it("labels process attribution without guessing", () => {
    expect(attributionLabel("attributed")).toBe("Process identified");
    expect(attributionLabel("not_found")).toBe("Process not found");
    expect(attributionLabel("unavailable")).toBe("Process unavailable");
    expect(attributionLabel("weird")).toBe("weird");
  });
});

describe("TLS run scope and reasons", () => {
  it("describes where a TLS run looks, and a filesystem run's scope as before", () => {
    expect(describeRunScope(makeRun({ type: "tls", config: {} }))).toBe("TLS listeners on this machine");
    expect(describeRunScope(makeRun({ type: "tls", config: { ports: [443, 8443] } }))).toBe("TLS listeners on this machine (ports 443, 8443)");
    expect(describeRunScope(makeRun({ type: "tls", config: { ports: "x" } }))).toBe("TLS listeners on this machine");
    expect(describeRunScope(makeRun({ type: "filesystem", config: { roots: ["C:\\a"] } }))).toBe("C:\\a");
    expect(describeRunScope(makeRun({ type: "filesystem", config: {} }))).toBe("Agent default locations");
  });

  it("translates the TLS stop reasons", () => {
    expect(explainToken("stopped_enumeration_failed")).toMatch(/could not read this machine's list of listening sockets/);
    expect(explainToken("stopped_target_limit")).toMatch(/target limit/);
    expect(explainToken("stopped_time_limit")).toMatch(/time budget/);
  });
});
