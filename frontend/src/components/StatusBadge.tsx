import { RUN_STATUSES } from "../api/types";

const LABELS: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  partial: "Partial",
  failed: "Failed",
};

/** The status as text first (colour is only a hint). An unrecognised status is shown as "Unknown", never trusted. */
export function StatusBadge({ status, cancelRequested = false }: { status: string; cancelRequested?: boolean }) {
  const known = (RUN_STATUSES as readonly string[]).includes(status);
  const label = known ? LABELS[status] : "Unknown";
  return (
    <span className={`badge badge-${known ? status : "unknown"}`}>
      {label}
      {cancelRequested && status === "running" ? " (cancelling)" : ""}
    </span>
  );
}
