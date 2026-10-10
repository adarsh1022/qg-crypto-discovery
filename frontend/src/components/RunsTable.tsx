import { isActive, type Run } from "../api/types";
import { DASH, describeOutcome, describeRunScope, formatDuration, formatTime, isWaitingForAgent } from "../format";
import { reportHref } from "../route";
import { StatusBadge } from "./StatusBadge";

export interface RowAction {
  busy: boolean;
  error: string | null;
}

interface Props {
  runs: Run[];
  nowMs: number;
  actions: Record<string, RowAction | undefined>;
  onCancel: (run: Run) => void;
}

/** Cancelling makes sense while a run is queued, or running and not yet asked to stop. */
export function canCancel(run: Pick<Run, "status" | "cancel_requested">): boolean {
  return run.status === "queued" || (run.status === "running" && !run.cancel_requested);
}

/** The trigger as the backend recorded it. A value this UI does not know is shown as it is (as text), never guessed at. */
function describeTrigger(trigger: string): string {
  if (trigger === "manual") return "Manual";
  if (trigger === "scheduled") return "Scheduled";
  return trigger;
}

export function RunsTable({ runs, nowMs, actions, onCancel }: Props) {
  return (
    <div className="table-wrap">
      <table>
        <caption className="sr-only">Discovery runs, newest first</caption>
        <thead>
          <tr>
            <th scope="col">Run</th>
            <th scope="col">Trigger</th>
            <th scope="col">Status</th>
            <th scope="col">Scope</th>
            <th scope="col">Queued</th>
            <th scope="col">Started</th>
            <th scope="col">Finished</th>
            <th scope="col">Duration</th>
            <th scope="col" className="num" title="Observation records the agent reported">Records</th>
            <th scope="col" className="num" title="Records that carry a certificate (one certificate seen in several files counts once per file)">Sightings</th>
            <th scope="col" className="num">Errors</th>
            <th scope="col">Outcome</th>
            <th scope="col">Action</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => {
            const action = actions[run.run_id];
            const outcome = describeOutcome(run);
            const started = run.status !== "queued";
            return (
              <tr key={run.run_id}>
                <th scope="row">
                  {started && (run.type === "filesystem" || run.type === "tls") ? (
                    <a href={reportHref(run.run_id)} title="Open this run's report">#{run.run_number}</a>
                  ) : (
                    <>#{run.run_number}</>
                  )}
                  <div className="muted">{run.type}</div>
                  <div className="muted"><code title={run.run_id}>{run.run_id.slice(0, 8)}</code></div>
                </th>
                <td>
                  {describeTrigger(run.trigger)}
                  {run.trigger === "scheduled" && run.schedule_id && <div className="muted">{run.schedule_id}</div>}
                </td>
                <td>
                  <StatusBadge status={run.status} cancelRequested={run.cancel_requested} />
                </td>
                <td className="scope" title={describeRunScope(run)}>
                  {describeRunScope(run)}
                </td>
                <td>{formatTime(run.queued_at)}</td>
                <td>{formatTime(run.started_at)}</td>
                <td>{formatTime(run.finished_at)}</td>
                <td>{formatDuration(run.duration_ms)}</td>
                <td className="num">{started ? run.record_count : DASH}</td>
                <td
                  className="num"
                  title={started && run.type === "tls" ? "Completed TLS handshakes, the only TLS findings. This is not a count of sightings." : undefined}
                >
                  {started ? run.finding_count : DASH}
                  {started && run.type === "tls" && <div className="muted">completed handshakes</div>}
                </td>
                <td className="num">
                  {started ? run.error_count : DASH}
                  {run.rejected_count > 0 && <div className="muted">{run.rejected_count} rejected</div>}
                </td>
                <td>
                  {isWaitingForAgent(run, nowMs) && (
                    <span className="warn">
                      Waiting for an agent. Start <code>python -m agent</code>.
                    </span>
                  )}
                  {outcome && <span className={run.status === "completed" ? "muted" : undefined}>{outcome}</span>}
                  {isActive(run) && !isWaitingForAgent(run, nowMs) && <span className="muted">In progress.</span>}
                  {action?.error && <div className="field-error" role="alert">{action.error}</div>}
                </td>
                <td>
                  {run.type === "filesystem" && run.status !== "queued" && (
                    <a className="button-link" href={reportHref(run.run_id)} aria-label={`Open report for run ${run.run_number}`}>
                      Report
                    </a>
                  )}
                  {run.type === "tls" && run.status !== "queued" && (
                    <a className="button-link" href={reportHref(run.run_id)} aria-label={`Open TLS report for run ${run.run_number}`}>
                      Report
                    </a>
                  )}
                  {canCancel(run) && (
                    <button type="button" onClick={() => onCancel(run)} disabled={action?.busy} aria-label={`Cancel run ${run.run_number}`}>
                      {action?.busy ? "Cancelling…" : "Cancel"}
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
