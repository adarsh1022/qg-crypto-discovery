// Turn a failure into one plain sentence for the user. Only fixed identifiers (status, error code, field names) are used:
// request bodies, scanned paths and server internals never reach the screen through here.
import { ApiError, NetworkError } from "./client";

const BY_CODE: Record<string, string> = {
  invalid_config: "The backend did not accept the scan settings.",
  validation_failed: "The request was not valid.",
  invalid_schedule: "The backend did not accept this schedule.",
  too_many_schedules: "The maximum number of schedules has been reached.",
  schedule_not_found: "That schedule no longer exists.",
  run_not_found: "That run no longer exists.",
  run_not_cancellable: "That run has already finished, so it can no longer be cancelled.",
  busy: "The backend is busy. Try again in a moment.",
  query_timeout: "The backend took too long to answer. Try again.",
  host_not_allowed: "The backend only answers on local addresses. Open this page via 127.0.0.1 or localhost.",
  origin_not_allowed: "The backend refused this page's origin. Open this page via 127.0.0.1 or localhost.",
  internal_error: "The backend hit an internal error.",
  invalid_response: "The backend sent a response this page does not understand.",
};

export function describeError(error: unknown): string {
  if (error instanceof NetworkError) {
    return error.reason === "timeout"
      ? "The backend did not answer in time."
      : "Cannot reach the backend. Is it running? (python -m backend)";
  }
  if (error instanceof ApiError) {
    return BY_CODE[error.code] ?? `The backend refused the request (${error.status} ${error.code}).`;
  }
  return "Something unexpected went wrong.";
}

/** For an invalid_config or invalid_schedule answer: which form field the backend objected to, if it said. */
export function offendingField(error: unknown): string | null {
  if (error instanceof ApiError && (error.code === "invalid_config" || error.code === "invalid_schedule") && typeof error.details.field === "string") {
    return error.details.field;
  }
  return null;
}
