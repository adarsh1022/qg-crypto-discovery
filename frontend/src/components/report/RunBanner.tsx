import type { Run } from "../../api/types";
import { explainRun, isWaitingForAgent, wasCancelled } from "../../format";

/**
 * What the run's outcome means for the data below. It is decided from the run's status and recorded reasons, never from
 * the size of the result: a failed run reports zeros just like a scan that found nothing.
 */
export function RunBanner({ run, nowMs, kind = "filesystem" }: { run: Run; nowMs: number; kind?: "filesystem" | "tls" }) {
  const tls = kind === "tls";
  const reasons = explainRun(run);
  const cancelled = wasCancelled(run);

  let tone = "info";
  let title: string;
  let body: string | null = null;
  switch (run.status) {
    case "queued":
      title = "Queued";
      body = isWaitingForAgent(run, nowMs)
        ? "No agent has picked this run up yet. Start one with python -m agent. The backend fails a run that waits too long."
        : "Waiting for an agent to pick this run up. There are no results yet.";
      break;
    case "running":
      title = run.cancel_requested ? "Running - cancellation requested" : "Scan in progress";
      body = "Everything below is what the agent has reported so far. It is incomplete and will keep changing until the run ends.";
      break;
    case "completed":
      tone = "ok";
      title = "Completed";
      body =
        run.record_count === 0
          ? tls
            ? "The scan ran to the end, but the agent reported no probe results, so there is nothing to list."
            : "The scan ran to the end, but the agent reported no records, so there is nothing to list."
          : tls
            ? "The scan ran to the end and no scan errors were recorded."
            : "The scan ran to the end and no errors were recorded.";
      break;
    case "partial":
      tone = "warn";
      title = cancelled ? "Cancelled - results are incomplete" : "Partial - results are incomplete";
      body = tls
        ? "What is listed below was recorded before the scan stopped or hit problems. Other listeners may exist that were not probed."
        : "What is listed below was found before the scan stopped or hit problems. Other certificates may exist that were not reached.";
      break;
    case "failed":
      tone = "bad";
      title = cancelled ? "Cancelled before any results were recorded" : "Failed";
      body =
        run.record_count > 0
          ? `${run.record_count} ${tls ? (run.record_count === 1 ? "probe result was" : "probe results were") : run.record_count === 1 ? "record was" : "records were"} stored before the run failed. Treat the data below as incomplete.`
          : tls
            ? "No probe results were recorded. An empty report here does not mean that no TLS services exist."
            : "No results were recorded. An empty report here does not mean that no certificates exist.";
      break;
    default:
      tone = "neutral";
      title = "Unknown status";
      body = "This page does not recognise the run's status, so it makes no claim about the results.";
  }

  return (
    <section className={`banner banner-${tone}`} role="status" aria-label="Run outcome">
      <strong>{title}</strong>
      {body && <p>{body}</p>}
      {reasons.length > 0 && (
        <ul>
          {reasons.map((reason, index) => (
            <li key={index}>{reason}</li>
          ))}
        </ul>
      )}
    </section>
  );
}
