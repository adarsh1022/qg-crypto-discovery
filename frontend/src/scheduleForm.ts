// Turning the "new schedule" form into the request body, and showing an interval in words. Pure and unit-tested.
//
// The scan settings reuse the same builders as the one-off scan forms, so a schedule can contain exactly what a manual run can.
// The limits (15 seconds to 7 days) are the backend's; the backend checks them again. A TLS schedule with no ports is only built
// when the user ticked the explicit opt-in, and the body then says so (`probe_all_listeners: true`), which the backend requires.
import { MAX_INTERVAL_SECONDS, MIN_INTERVAL_SECONDS, type CreateScheduleBody } from "./api/types";
import { buildConfig, buildTlsConfig, EMPTY_FORM, EMPTY_TLS_FORM } from "./scanForm";

export type IntervalUnit = "seconds" | "minutes" | "hours" | "days";
export const INTERVAL_UNITS: ReadonlyArray<readonly [IntervalUnit, number]> = [
  ["seconds", 1],
  ["minutes", 60],
  ["hours", 3600],
  ["days", 86_400],
];

export interface ScheduleFormValues {
  kind: "filesystem" | "tls";
  amount: string; // a whole number
  unit: IntervalUnit;
  roots: string; // filesystem: one absolute folder per line
  useStandardFolders: boolean; // filesystem: the explicit choice to scan the agent's built-in locations
  ports: string; // tls: whole numbers separated by spaces, commas or semicolons
  probeAll: boolean; // tls: the explicit opt-in to probe every eligible listener when no ports are given
}

export const EMPTY_SCHEDULE_FORM: ScheduleFormValues = {
  kind: "filesystem",
  amount: "",
  unit: "minutes",
  roots: "",
  useStandardFolders: false,
  ports: "",
  probeAll: false,
};

export type ScheduleFormErrors = Partial<Record<"interval" | "roots" | "ports", string>>;

const INTERVAL_PROBLEM = "Choose a whole number of seconds, minutes, hours or days from 15 seconds to 7 days.";

/** The interval in seconds, or the sentence that says what is wrong. */
export function parseInterval(amount: string, unit: IntervalUnit): number | string {
  const text = amount.trim();
  if (!/^\d{1,9}$/.test(text)) return INTERVAL_PROBLEM;
  const factor = INTERVAL_UNITS.find(([name]) => name === unit)?.[1];
  if (factor === undefined) return INTERVAL_PROBLEM;
  const seconds = Number(text) * factor;
  return seconds >= MIN_INTERVAL_SECONDS && seconds <= MAX_INTERVAL_SECONDS ? seconds : INTERVAL_PROBLEM;
}

export function buildScheduleBody(values: ScheduleFormValues): { body: CreateScheduleBody | null; errors: ScheduleFormErrors } {
  const errors: ScheduleFormErrors = {};
  const interval = parseInterval(values.amount, values.unit);
  if (typeof interval === "string") errors.interval = interval;

  let body: CreateScheduleBody | null = null;
  if (values.kind === "filesystem") {
    const built = buildConfig({ ...EMPTY_FORM, roots: values.roots, useDefaultLocations: values.useStandardFolders });
    if (built.errors.roots) errors.roots = built.errors.roots;
    if (built.config && typeof interval === "number") body = { run_type: "filesystem", interval_seconds: interval, config: built.config };
  } else {
    const built = buildTlsConfig({ ...EMPTY_TLS_FORM, ports: values.ports, probeAll: values.probeAll });
    if (built.errors.ports) errors.ports = built.errors.ports;
    if (built.config && typeof interval === "number") {
      body = { run_type: "tls", interval_seconds: interval, config: built.config, ...(values.probeAll ? { probe_all_listeners: true } : {}) };
    }
  }
  return Object.keys(errors).length > 0 ? { body: null, errors } : { body, errors };
}

/** 90 -> "1 min 30 s", 3600 -> "1 h", 604800 -> "7 days": exact, never rounded. */
export function formatInterval(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "–";
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = Math.floor(seconds % 60);
  const parts = [
    days ? `${days} ${days === 1 ? "day" : "days"}` : "",
    hours ? `${hours} h` : "",
    minutes ? `${minutes} min` : "",
    rest ? `${rest} s` : "",
  ].filter(Boolean);
  return parts.length > 0 ? parts.join(" ") : "0 s";
}
