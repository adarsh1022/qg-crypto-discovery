import { useState, type FormEvent } from "react";
import { createSchedule } from "../api/client";
import { describeError, offendingField } from "../api/describe";
import type { Schedule } from "../api/types";
import { buildScheduleBody, EMPTY_SCHEDULE_FORM, INTERVAL_UNITS, type IntervalUnit, type ScheduleFormErrors, type ScheduleFormValues } from "../scheduleForm";
import { ErrorPanel } from "./ErrorPanel";

/**
 * Create a periodic scan. The scan settings are the same as for a one-off scan and never name a host or address; a TLS
 * schedule without ports probes every eligible listener on this machine each time it fires, so it needs the explicit opt-in
 * (and the backend refuses it without). Nothing is created until the backend has accepted the schedule.
 */
export function NewScheduleForm({ onCreated }: { onCreated: (schedule: Schedule) => void }) {
  const [values, setValues] = useState<ScheduleFormValues>(EMPTY_SCHEDULE_FORM);
  const [errors, setErrors] = useState<ScheduleFormErrors>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const set = <K extends keyof ScheduleFormValues>(key: K, value: ScheduleFormValues[K]) => setValues((v) => ({ ...v, [key]: value }));

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (submitting) return;
    const { body, errors: found } = buildScheduleBody(values);
    setErrors(found);
    setFailure(null);
    if (!body) return;
    setSubmitting(true);
    try {
      const schedule = await createSchedule(body);
      setValues(EMPTY_SCHEDULE_FORM);
      onCreated(schedule);
    } catch (error) {
      const field = offendingField(error);
      if (field === "interval_seconds") setErrors({ interval: "The backend did not accept this interval." });
      else if (field === "probe_all_listeners") setErrors({ ports: "The backend needs ports or the explicit opt-in for a TLS schedule." });
      else if (field === "roots" || field === "ports") setErrors({ [field]: "The backend did not accept this value." });
      else setFailure(describeError(error));
    } finally {
      setSubmitting(false);
    }
  }

  const tls = values.kind === "tls";
  return (
    <form className="card" onSubmit={submit} noValidate aria-labelledby="new-schedule-title">
      <h3 id="new-schedule-title">Schedule settings</h3>

      <div className="field">
        <label htmlFor="schedule-kind">Kind of scan</label>
        <select id="schedule-kind" value={values.kind} disabled={submitting} onChange={(e) => set("kind", e.target.value as ScheduleFormValues["kind"])}>
          <option value="filesystem">Filesystem scan</option>
          <option value="tls">TLS metadata scan</option>
        </select>
      </div>

      <div className="field">
        <label htmlFor="schedule-amount">Run every</label>
        <div className="inline-fields">
          <input
            id="schedule-amount"
            inputMode="numeric"
            value={values.amount}
            disabled={submitting}
            onChange={(e) => set("amount", e.target.value)}
            aria-invalid={errors.interval ? true : undefined}
            aria-describedby={errors.interval ? "schedule-interval-hint schedule-interval-error" : "schedule-interval-hint"}
          />
          <select aria-label="Interval unit" value={values.unit} disabled={submitting} onChange={(e) => set("unit", e.target.value as IntervalUnit)}>
            {INTERVAL_UNITS.map(([unit]) => (
              <option key={unit} value={unit}>{unit}</option>
            ))}
          </select>
        </div>
        <p className="hint" id="schedule-interval-hint">
          From 15 seconds to 7 days. The first run is due one full interval after the schedule is created. A run that falls due while
          another scan is waiting for the agent or in progress is skipped, and a schedule that was missed while the backend was stopped
          runs once, not once per missed interval. Scheduled scans need the agent to be started.
        </p>
        {errors.interval && <p className="field-error" id="schedule-interval-error" role="alert">{errors.interval}</p>}
      </div>

      {!tls && (
        <>
          <div className="field">
            <label htmlFor="schedule-roots">Folders for this schedule (one per line)</label>
            <textarea
              id="schedule-roots"
              rows={3}
              value={values.roots}
              disabled={values.useStandardFolders || submitting}
              onChange={(e) => set("roots", e.target.value)}
              aria-invalid={errors.roots ? true : undefined}
              aria-describedby={errors.roots ? "schedule-roots-error" : undefined}
              spellCheck={false}
            />
            <p className="hint">Absolute local paths, for example C:\Users\you\certs</p>
            {errors.roots && <p className="field-error" id="schedule-roots-error" role="alert">{errors.roots}</p>}
          </div>
          <div className="field checkbox">
            <input id="schedule-standard" type="checkbox" checked={values.useStandardFolders} disabled={submitting} onChange={(e) => set("useStandardFolders", e.target.checked)} />
            <label htmlFor="schedule-standard">Use the agent&apos;s standard folders instead</label>
            <p className="hint">Broad: Downloads, Documents, Desktop, ProgramData and a few others. Each run can take several minutes.</p>
          </div>
        </>
      )}

      {tls && (
        <>
          <p className="hint">
            Each run makes a TLS handshake attempt against listening TCP services on this machine (an active probe, not traffic capture). It
            cannot be pointed at another host.
          </p>
          <div className="field">
            <label htmlFor="schedule-ports">Ports for this schedule</label>
            <input
              id="schedule-ports"
              value={values.ports}
              disabled={values.probeAll || submitting}
              onChange={(e) => set("ports", e.target.value)}
              aria-invalid={errors.ports ? true : undefined}
              aria-describedby={errors.ports ? "schedule-ports-error" : undefined}
              spellCheck={false}
            />
            <p className="hint">Whole numbers from 1 to 65535, separated by spaces or commas. Only listeners that are open on this machine are probed.</p>
            {errors.ports && <p className="field-error" id="schedule-ports-error" role="alert">{errors.ports}</p>}
          </div>
          <div className="field checkbox">
            <input id="schedule-probe-all" type="checkbox" checked={values.probeAll} disabled={submitting} onChange={(e) => set("probeAll", e.target.checked)} aria-describedby="schedule-probe-all-hint" />
            <label htmlFor="schedule-probe-all">Probe all eligible TLS listeners every time (broad)</label>
            <p className="hint warn-text" id="schedule-probe-all-hint">
              Every run would probe every listening TCP socket on this machine that passes the target policy, up to 128 targets, and
              non-TLS services may log each attempt. List ports instead to keep a recurring scan narrow.
            </p>
          </div>
        </>
      )}

      {failure && <ErrorPanel>{failure}</ErrorPanel>}
      <div className="actions">
        <button type="submit" className="primary" disabled={submitting}>
          {submitting ? "Creating\u2026" : "Create schedule"}
        </button>
      </div>
    </form>
  );
}
