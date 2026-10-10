import { useState } from "react";
import { listSchedules, setScheduleEnabled } from "../api/client";
import { describeError } from "../api/describe";
import { SCHEDULE_STATES, type Schedule } from "../api/types";
import { describeRunScope, formatTime } from "../format";
import { useResource } from "../hooks/useResource";
import { reportHref } from "../route";
import { formatInterval } from "../scheduleForm";
import { NewScheduleForm } from "./NewScheduleForm";
import { StatusBadge } from "./StatusBadge";

const STATE_LABEL: Record<string, string> = { waiting: "Waiting", skipping: "Skipping", paused: "Paused" };
const STATE_NOTE: Record<string, string> = {
  waiting: "Nothing else is running. The next run starts when it falls due.",
  skipping: "Another scan is waiting for the agent or in progress, so a run that falls due now is skipped.",
  paused: "No runs are created until it is resumed.",
};

/** The state as the backend reported it. An unknown state is shown as "Unknown", never as one of the known ones. */
export function ScheduleStateBadge({ state }: { state: string }) {
  const known = (SCHEDULE_STATES as readonly string[]).includes(state);
  return <span className={`badge badge-schedule-${known ? state : "unknown"}`}>{known ? STATE_LABEL[state] : "Unknown"}</span>;
}

function ScheduleItem({ schedule, onChanged }: { schedule: Schedule; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const known = (SCHEDULE_STATES as readonly string[]).includes(schedule.state);

  async function toggle() {
    if (busy) return;
    setBusy(true);
    setProblem(null);
    try {
      await setScheduleEnabled(schedule.schedule_id, !schedule.enabled);
      onChanged();
    } catch (error) {
      setProblem(describeError(error));
      onChanged(); // the schedule may have changed meanwhile: show what it is now
    } finally {
      setBusy(false);
    }
  }

  const last = schedule.last_run;
  const verb = schedule.enabled ? "Pause" : "Resume";
  return (
    <li className="schedule-item" aria-label={`Schedule ${schedule.schedule_id}`}>
      <div className="schedule-head">
        <strong>{schedule.run_type === "tls" ? "TLS metadata scan" : "Filesystem scan"}</strong>
        <ScheduleStateBadge state={schedule.state} />
        <span className="muted">every {formatInterval(schedule.interval_seconds)}</span>
        <code className="muted" title="Schedule id: scheduled runs carry it in the runs list">{schedule.schedule_id}</code>
      </div>
      <div className="path" title={describeRunScope({ type: schedule.run_type, config: schedule.config })}>
        {describeRunScope({ type: schedule.run_type, config: schedule.config })}
      </div>
      {schedule.run_type === "tls" && schedule.probe_all_listeners && (
        <p className="hint warn-text">Probes every eligible TLS listener on this machine each time (broad).</p>
      )}
      <dl className="facts schedule-facts">
        <dt>Next run</dt>
        <dd>{schedule.enabled ? formatTime(schedule.next_due_at) : "–"}</dd>
        <dt>Last run</dt>
        <dd>
          {last ? (
            <>
              <a href={reportHref(last.run_id)} title="Open this run's report">#{last.run_number}</a> <StatusBadge status={last.status} />
            </>
          ) : (
            "None yet"
          )}
        </dd>
        <dt>Runs so far</dt>
        <dd>{schedule.run_count}</dd>
      </dl>
      {known && <p className="hint">{STATE_NOTE[schedule.state]}</p>}
      <div className="actions">
        <button type="button" onClick={() => void toggle()} disabled={busy} aria-label={`${verb} schedule ${schedule.schedule_id}`}>
          {busy ? `${verb === "Pause" ? "Pausing" : "Resuming"}…` : verb}
        </button>
      </div>
      {problem && <p className="field-error" role="alert">{problem}</p>}
    </li>
  );
}

/**
 * Periodic scans: the list the backend holds (read again every few seconds while the page is in use), a compact form to add
 * one, and pause/resume. Everything shown is what the backend returned; nothing here predicts a run or a result.
 */
export function SchedulesPanel({ active = true }: { active?: boolean }) {
  const schedules = useResource((signal) => listSchedules(signal), [], { pollWhile: () => active });
  const [created, setCreated] = useState<Schedule | null>(null);
  const [formOpen, setFormOpen] = useState(false);

  return (
    <section aria-labelledby="schedules-title" className="schedules">
      <div className="toolbar">
        <h2 id="schedules-title">Scheduled scans</h2>
      </div>
      <p className="muted">
        A schedule starts a scan on its own, every interval. Its runs appear in the list below with the trigger Scheduled. The agent has
        to be running to pick them up.
      </p>

      <details className="new-scan" open={formOpen} onToggle={(e) => setFormOpen(e.currentTarget.open)}>
        <summary>New schedule</summary>
        <NewScheduleForm
          onCreated={(schedule) => {
            setCreated(schedule);
            setFormOpen(false);
            void schedules.reload();
          }}
        />
      </details>
      <div aria-live="polite" className="notice">
        {created && `Schedule ${created.schedule_id} created. Its first run is due ${formatTime(created.next_due_at)}.`}
      </div>

      {schedules.phase === "loading" && <p aria-live="polite">Loading schedules&hellip;</p>}
      {schedules.phase === "error" && (
        <p className="muted" aria-live="polite">
          Could not load the schedules. {describeError(schedules.error)}{" "}
          <button type="button" onClick={() => void schedules.reload()} disabled={schedules.reloading}>
            {schedules.reloading ? "Retrying…" : "Retry"}
          </button>
        </p>
      )}
      {schedules.phase === "ready" && schedules.stale && (
        <p className="muted" aria-live="polite">
          Could not refresh the schedules ({describeError(schedules.error)}). Showing the last list that loaded; it may be out of date.
        </p>
      )}
      {schedules.phase === "ready" && schedules.data !== null && schedules.data.length === 0 && (
        <p className="empty">No schedules yet. Create one to run a scan automatically.</p>
      )}
      {schedules.data !== null && schedules.data.length > 0 && (
        <ul className="schedule-list" aria-label="Scheduled scans">
          {schedules.data.map((schedule) => (
            <ScheduleItem key={schedule.schedule_id} schedule={schedule} onChanged={() => void schedules.reload()} />
          ))}
        </ul>
      )}
    </section>
  );
}
