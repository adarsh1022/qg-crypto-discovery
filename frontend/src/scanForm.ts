// Turning the "new filesystem scan" form into a run configuration. Pure and unit-tested.
// Only light checks live here; the backend checks the shape and the agent has the final say (it fails a run whose
// settings it cannot use). Nothing is silently broad: with no folders and no explicit opt-in this returns an error.
import type { FsConfig, TlsConfig } from "./api/types";

export interface ScanFormValues {
  roots: string; // one absolute folder per line
  useDefaultLocations: boolean;
  extensions: string; // separated by spaces, commas or semicolons
  excludePaths: string; // one absolute path per line
  maxDepth: string;
  timeBudgetSeconds: string;
  expiringDays: string;
}

export const EMPTY_FORM: ScanFormValues = {
  roots: "",
  useDefaultLocations: false,
  extensions: "",
  excludePaths: "",
  maxDepth: "",
  timeBudgetSeconds: "",
  expiringDays: "",
};

export type FormErrors = Partial<Record<"roots" | "extensions" | "exclude_paths" | "max_depth" | "time_budget_seconds" | "expiring_days", string>>;

const DRIVE_PATH = /^[A-Za-z]:[\\/]/;
const EXTENSION = /^\.?[A-Za-z0-9]{1,16}$/;
const MAX_NUMBER = 1e12;

function lines(text: string): string[] {
  return [...new Set(text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean))];
}

function absolutePathProblem(path: string): string | null {
  if (path.startsWith("\\\\") || path.startsWith("//")) return "Network (UNC) paths are not supported.";
  if (!DRIVE_PATH.test(path)) return "Use an absolute local path such as C:\\Users\\you\\certs.";
  if (path.length > 1000) return "That path is too long.";
  return null;
}

function wholeNumber(text: string, minimum: number): number | string {
  if (!/^\d{1,13}$/.test(text)) return "Enter a whole number.";
  const value = Number(text);
  if (value < minimum || value > MAX_NUMBER) return minimum > 0 ? "Enter a number above 0." : "Enter a number of 0 or more.";
  return value;
}

export function buildConfig(values: ScanFormValues): { config: FsConfig | null; errors: FormErrors } {
  const errors: FormErrors = {};
  const config: FsConfig = {};

  if (values.useDefaultLocations) {
    // roots stays out of the configuration on purpose: the agent then scans its own default locations.
  } else {
    const roots = lines(values.roots);
    if (roots.length === 0) {
      errors.roots = "Enter at least one folder to scan, or choose the agent's default locations.";
    } else {
      const bad = roots.map(absolutePathProblem).find((p) => p !== null);
      if (bad) errors.roots = bad;
      else if (roots.length > 200) errors.roots = "At most 200 folders.";
      else config.roots = roots;
    }
  }

  const extensions = values.extensions.split(/[\s,;]+/).filter(Boolean);
  if (extensions.length > 0) {
    if (extensions.some((e) => !EXTENSION.test(e))) errors.extensions = "Use file extensions such as .pem .crt .pfx.";
    else config.extensions = extensions;
  }

  const excluded = lines(values.excludePaths);
  if (excluded.length > 0) {
    const bad = excluded.map(absolutePathProblem).find((p) => p !== null);
    if (bad) errors.exclude_paths = bad;
    else config.exclude_paths = excluded;
  }

  const numeric: Array<[string, "max_depth" | "expiring_days" | "time_budget_seconds", number]> = [
    [values.maxDepth.trim(), "max_depth", 0],
    [values.expiringDays.trim(), "expiring_days", 0],
    [values.timeBudgetSeconds.trim(), "time_budget_seconds", 1],
  ];
  for (const [text, key, minimum] of numeric) {
    if (text === "") continue;
    const parsed = wholeNumber(text, minimum);
    if (typeof parsed === "string") errors[key] = parsed;
    else config[key] = parsed;
  }

  return Object.keys(errors).length > 0 ? { config: null, errors } : { config, errors };
}

// ------------------------------------------------------------------------------------------------------------------ TLS
// Turning the "new TLS metadata scan" form into a run configuration. The limits are the backend's (service.TLS_*); the
// agent's TlsScanConfig has the final say. The form can only NARROW what the agent finds in the operating system's table of
// listening sockets: it has no way to name a host or an address. With no ports and no explicit opt-in this returns an error,
// so a broad probe of every eligible listener on the machine can never happen by accident.

export interface TlsFormValues {
  ports: string; // whole numbers separated by spaces, commas or semicolons
  probeAll: boolean; // explicit opt-in to probe every eligible listener when no ports are given
  maxTargets: string;
  connectTimeoutSeconds: string;
  handshakeTimeoutSeconds: string;
  timeBudgetSeconds: string;
}

export const EMPTY_TLS_FORM: TlsFormValues = {
  ports: "",
  probeAll: false,
  maxTargets: "",
  connectTimeoutSeconds: "",
  handshakeTimeoutSeconds: "",
  timeBudgetSeconds: "",
};

export type TlsFormErrors = Partial<
  Record<"ports" | "max_targets" | "connect_timeout_seconds" | "handshake_timeout_seconds" | "time_budget_seconds", string>
>;

export const TLS_MAX_PORTS = 256;
export const TLS_MAX_TARGETS = 1024;
export const TLS_MAX_TIMEOUT_SECONDS = 30;
export const TLS_MAX_BUDGET_SECONDS = 3600;

const PORT_TOKEN = /^\d{1,5}$/;
const DECIMAL = /^\d{1,6}(\.\d{1,6})?$/;

function secondsBelow(text: string, ceiling: number): number | string {
  const value = DECIMAL.test(text) ? Number(text) : Number.NaN;
  if (!(value > 0 && value <= ceiling)) return `Enter a number above 0 and at most ${ceiling}.`;
  return value;
}

export function buildTlsConfig(values: TlsFormValues): { config: TlsConfig | null; errors: TlsFormErrors } {
  const errors: TlsFormErrors = {};
  const config: TlsConfig = {};

  if (!values.probeAll) {
    const tokens = values.ports.split(/[\s,;]+/).filter(Boolean);
    if (tokens.length === 0) {
      errors.ports = "Enter at least one port, or tick the box to probe every eligible listener on this machine.";
    } else {
      const ports = tokens.map((t) => (PORT_TOKEN.test(t) ? Number(t) : Number.NaN));
      if (ports.some((p) => !(p >= 1 && p <= 65535))) errors.ports = "Ports are whole numbers from 1 to 65535, separated by spaces or commas.";
      else {
        const unique = [...new Set(ports)];
        if (unique.length > TLS_MAX_PORTS) errors.ports = `At most ${TLS_MAX_PORTS} ports.`;
        else config.ports = unique;
      }
    }
  } // with the opt-in, `ports` stays out of the configuration on purpose: the agent then considers every eligible listener.

  const targets = values.maxTargets.trim();
  if (targets !== "") {
    const value = /^\d{1,5}$/.test(targets) ? Number(targets) : Number.NaN;
    if (!(value >= 1 && value <= TLS_MAX_TARGETS)) errors.max_targets = `Enter a whole number from 1 to ${TLS_MAX_TARGETS}.`;
    else config.max_targets = value;
  }

  const seconds: Array<[string, "connect_timeout_seconds" | "handshake_timeout_seconds" | "time_budget_seconds", number]> = [
    [values.connectTimeoutSeconds.trim(), "connect_timeout_seconds", TLS_MAX_TIMEOUT_SECONDS],
    [values.handshakeTimeoutSeconds.trim(), "handshake_timeout_seconds", TLS_MAX_TIMEOUT_SECONDS],
    [values.timeBudgetSeconds.trim(), "time_budget_seconds", TLS_MAX_BUDGET_SECONDS],
  ];
  for (const [text, key, ceiling] of seconds) {
    if (text === "") continue;
    const parsed = secondsBelow(text, ceiling);
    if (typeof parsed === "string") errors[key] = parsed;
    else config[key] = parsed;
  }

  return Object.keys(errors).length > 0 ? { config: null, errors } : { config, errors };
}
