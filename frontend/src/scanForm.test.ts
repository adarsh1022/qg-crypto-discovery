import { describe, expect, it } from "vitest";
import { buildConfig, EMPTY_FORM, type ScanFormValues } from "./scanForm";

const form = (over: Partial<ScanFormValues>): ScanFormValues => ({ ...EMPTY_FORM, ...over });

describe("buildConfig", () => {
  it("requires a folder: an empty form never turns into a broad default scan", () => {
    const { config, errors } = buildConfig(EMPTY_FORM);
    expect(config).toBeNull();
    expect(errors.roots).toMatch(/at least one folder/i);
    expect(buildConfig(form({ roots: "  \n \n" })).config).toBeNull();
  });

  it("sends only the folders when nothing else is set", () => {
    expect(buildConfig(form({ roots: "C:\\certs\n  D:/more  \nC:\\certs" })).config).toEqual({ roots: ["C:\\certs", "D:/more"] });
  });

  it("omits roots only when the default locations are chosen explicitly", () => {
    expect(buildConfig(form({ useDefaultLocations: true, roots: "C:\\ignored" })).config).toEqual({});
  });

  it.each([["relative\\dir"], ["\\\\server\\share"], ["//server/share"], ["C:"], ["/etc"], ["~/certs"]])("rejects the folder %s", (root) => {
    const { config, errors } = buildConfig(form({ roots: `C:\\ok\n${root}` }));
    expect(config).toBeNull();
    expect(errors.roots).toBeTruthy();
  });

  it("builds the advanced options with the backend's key names", () => {
    const { config } = buildConfig(form({
      roots: "C:\\certs", extensions: ".pem, crt;.pfx", excludePaths: "C:\\certs\\old", maxDepth: "0", timeBudgetSeconds: "90", expiringDays: "45",
    }));
    expect(config).toEqual({
      roots: ["C:\\certs"], extensions: [".pem", "crt", ".pfx"], exclude_paths: ["C:\\certs\\old"], max_depth: 0, time_budget_seconds: 90, expiring_days: 45,
    });
  });

  it.each([
    [{ extensions: "pem/../x" }, "extensions"],
    [{ extensions: "a b!" }, "extensions"],
    [{ excludePaths: "relative" }, "exclude_paths"],
    [{ maxDepth: "-1" }, "max_depth"],
    [{ maxDepth: "1.5" }, "max_depth"],
    [{ maxDepth: "abc" }, "max_depth"],
    [{ timeBudgetSeconds: "0" }, "time_budget_seconds"],
    [{ timeBudgetSeconds: "1e9" }, "time_budget_seconds"],
    [{ expiringDays: "99999999999999" }, "expiring_days"],
  ] as const)("flags %j", (over, field) => {
    const { config, errors } = buildConfig(form({ roots: "C:\\certs", ...over }));
    expect(config).toBeNull();
    expect(errors[field]).toBeTruthy();
  });

  it("reports every problem at once", () => {
    const { errors } = buildConfig(form({ roots: "nope", maxDepth: "x", expiringDays: "y" }));
    expect(Object.keys(errors).sort()).toEqual(["expiring_days", "max_depth", "roots"]);
  });
});
