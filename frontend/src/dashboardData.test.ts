import { describe, expect, it } from "vitest";
import {
  cipherRows, expiringOrExpired, finishedRuns, keyAlgorithmRows, runsByStatusAndType, signatureRows, tlsVersionRows, totalRuns, validityRows,
} from "./dashboardData";
import { makeDashboardSummary, makeStats } from "./test/dashboardFixtures";
import { makeRun } from "./test/helpers";
import { makeTlsSummary } from "./test/tlsFixtures";

const run = makeRun({ run_number: 3 });
const tlsRun = makeRun({ run_number: 4, type: "tls", config: {} });

describe("runs by status and type (GET /api/runs/stats: by_type_status)", () => {
  const stats = makeStats([
    { type: "filesystem", status: "completed", count: 3 },
    { type: "tls", status: "completed", count: 2 },
    { type: "filesystem", status: "failed", count: 1 },
    { type: "tls", status: "partial", count: 1 },
    { type: "tls", status: "running", count: 1 },
  ]);

  it("has one row per status in lifecycle order, and each row is the sum of its type segments", () => {
    const { rows, total } = runsByStatusAndType(stats);
    expect(rows.map((r) => [r.key, r.value])).toEqual([["queued", 0], ["running", 1], ["completed", 5], ["partial", 1], ["failed", 1]]);
    expect(total).toBe(8);
    const completed = rows.find((r) => r.key === "completed")!;
    expect(completed.segments!.map((s) => [s.label, s.value])).toEqual([["Filesystem", 3], ["TLS", 2]]);
    expect(completed.value).toBe(completed.segments!.reduce((n, s) => n + s.value, 0));
  });

  it("builds the legend from the types the data actually contains, filesystem first", () => {
    expect(runsByStatusAndType(stats).legend.map((l) => l.label)).toEqual(["Filesystem", "TLS"]);
    expect(runsByStatusAndType(makeStats([{ type: "tls", status: "completed", count: 1 }])).legend.map((l) => l.label)).toEqual(["TLS"]);
  });

  it("is all zeros, never invented counts, for no data", () => {
    const { rows, legend, total } = runsByStatusAndType(makeStats([]));
    expect(total).toBe(0);
    expect(legend).toEqual([]);
    expect(rows.every((r) => r.value === 0)).toBe(true);
  });

  it("totals and finished counts match the response", () => {
    expect(totalRuns(stats)).toBe(8);
    expect(finishedRuns(stats)).toBe(7);                      // completed 5 + partial 1 + failed 1; the running one is not finished
  });

  it("keeps a type it does not know about, under its own name", () => {
    const { rows } = runsByStatusAndType(makeStats([{ type: "future", status: "completed", count: 2 }]));
    expect(rows.find((r) => r.key === "completed")!.segments!.map((s) => [s.label, s.value])).toEqual([["future", 2]]);
  });
});

describe("certificate validity (summary.validity.now.unique and expiring_days)", () => {
  it("maps the four categories with an icon each, and names the expiry window from the response", () => {
    const rows = validityRows(makeDashboardSummary(run));
    expect(rows.map((r) => [r.key, r.label, r.value, r.icon])).toEqual([
      ["valid", "Valid", 5, "✓"], ["expiring", "Expiring within 30 days", 2, "!"], ["expired", "Expired", 1, "✕"], ["not_yet_valid", "Not yet valid", 0, "…"],
    ]);
  });

  it("uses the window the backend reports, in the singular when it is one day", () => {
    const summary = makeDashboardSummary(run, { expiring_days: { value: 1, source: "config" } });
    expect(validityRows(summary)[1].label).toBe("Expiring within 1 day");
  });

  it("counts expiring plus expired for the headline figure", () => {
    expect(expiringOrExpired(makeDashboardSummary(run))).toBe(3);
  });
});

describe("algorithms (summary.algorithms and summary.signature_algorithms)", () => {
  it("labels keys as algorithm plus size or curve, keeps the backend's ranking, and adds the 'other' group", () => {
    const rows = keyAlgorithmRows(makeDashboardSummary(run));
    expect(rows.map((r) => [r.label, r.value, r.detail])).toEqual([["RSA 2048", 4, "(6 sightings)"], ["EC P-256", 2, undefined], ["Other (2 more)", 2, undefined]]);
    expect(rows[2].tone).toBe("neutral");
  });

  it("shows an unknown algorithm as Unknown, not as a made-up name", () => {
    const summary = makeDashboardSummary(run, { algorithms: { top: [{ key_algorithm: null, key_size: null, key_curve: null, unique: 1, sightings: 1 }], other: null, total_groups: 1, limit: 10 } });
    expect(keyAlgorithmRows(summary).map((r) => r.label)).toEqual(["Unknown"]);
  });

  it("maps signature algorithms the same way, with no 'other' row when there is none", () => {
    const rows = signatureRows(makeDashboardSummary(run));
    expect(rows.map((r) => [r.label, r.value, r.detail])).toEqual([["sha256WithRSAEncryption", 6, "(7 sightings)"], ["ecdsa-with-SHA256", 2, undefined]]);
  });
});

describe("TLS (GET /api/runs/{id}/tls/summary: tls_versions and cipher_suites, completed handshakes only)", () => {
  const summary = makeTlsSummary(tlsRun, {
    tls_versions: { SSL3: 0, "TLS1.0": 0, "TLS1.1": 0, "TLS1.2": 1, "TLS1.3": 3 },
    cipher_suites: { top: [{ cipher_suite: "TLS_AES_256_GCM_SHA384", handshakes: 3 }, { cipher_suite: null, handshakes: 1 }], other: { groups: 2, handshakes: 1 }, total_groups: 4, limit: 2 },
  });

  it("lists only the versions that were negotiated, oldest first", () => {
    expect(tlsVersionRows(summary).map((r) => [r.label, r.value])).toEqual([["TLS1.2", 1], ["TLS1.3", 3]]);
  });

  it("is empty when no handshake negotiated a version", () => {
    expect(tlsVersionRows(makeTlsSummary(tlsRun))).toEqual([]);
  });

  it("keeps a version name it does not know about", () => {
    const odd = makeTlsSummary(tlsRun, { tls_versions: { "TLS1.3": 1, "TLS2.0": 2 } });
    expect(tlsVersionRows(odd).map((r) => r.label)).toEqual(["TLS1.3", "TLS2.0"]);
  });

  it("maps cipher suites in the backend's order, a missing name as 'Not reported', and the 'other' group", () => {
    expect(cipherRows(summary).map((r) => [r.label, r.value])).toEqual([["TLS_AES_256_GCM_SHA384", 3], ["Not reported", 1], ["Other (2 more)", 1]]);
  });
});
