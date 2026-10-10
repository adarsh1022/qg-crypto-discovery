import { useEffect, useRef, useState } from "react";
import { cancelRun } from "../api/client";
import { describeError } from "../api/describe";
import { RUN_STATUSES, RUN_TYPES, type Run, type RunFilters, type RunStatus, type RunType } from "../api/types";
import { ErrorPanel } from "../components/ErrorPanel";
import { NewScanPanel } from "../components/NewScanPanel";
import { RunsTable, type RowAction } from "../components/RunsTable";
import { SchedulesPanel } from "../components/SchedulesPanel";
import { useRunList } from "../hooks/useRunList";

/**
 * The line under the form about the run the user just created. It follows that run's real state (taken from the list as it
 * refreshes) so it never keeps saying "queued" after the run has moved on; if the run is not in the list (a filter hides it)
 * it only says the run was created.
 */
export function createdNotice(number: number, run: Run | undefined): { text: string; bad: boolean } {
  if (!run) return { text: `Run #${number} was created.`, bad: false };
  switch (run.status) {
    case "queued":
      return { text: `Run #${number} is queued. Waiting for an agent to pick it up.`, bad: false };
    case "running":
      return { text: `Run #${number} is running.`, bad: false };
    case "completed": {
      const none = run.type === "tls" ? "no probe results" : "no records";
      return { text: `Run #${number} completed${run.record_count === 0 ? `, but the agent reported ${none}` : ""}.`, bad: false };
    }
    case "partial":
      return { text: `Run #${number} ended with incomplete results.`, bad: true };
    case "failed":
      return { text: `Run #${number} failed.`, bad: true };
    default:
      return { text: `Run #${number} was created.`, bad: false };
  }
}

export function RunsPage({ active = true }: { active?: boolean }) {
  const [filters, setFilters] = useState<RunFilters>({});
  const { state, refresh, loadMore, replaceRun } = useRunList(filters, active);
  const [actions, setActions] = useState<Record<string, RowAction | undefined>>({});
  const [created, setCreated] = useState<{ id: string; number: number } | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  // The form is open for a first-time user (no runs yet) and tucked away once there are runs, so the list is what you see.
  const [formOpen, setFormOpen] = useState(true);
  const decided = useRef(false);
  useEffect(() => {
    if (state.phase === "ready" && !decided.current) {
      decided.current = true;
      setFormOpen(state.runs.length === 0);
    }
  }, [state.phase, state.runs.length]);

  useEffect(() => setNowMs(Date.now()), [state.runs]); // re-evaluates "waiting for an agent" on every refresh

  function onCreated(run: Run) {
    setCreated({ id: run.run_id, number: run.run_number });
    decided.current = true;
    setFormOpen(false); // show the new run in the list
    void refresh();
  }

  async function onCancel(run: Run) {
    setActions((a) => ({ ...a, [run.run_id]: { busy: true, error: null } }));
    try {
      replaceRun(await cancelRun(run.run_id));
      setActions((a) => ({ ...a, [run.run_id]: undefined }));
    } catch (error) {
      setActions((a) => ({ ...a, [run.run_id]: { busy: false, error: describeError(error) } }));
      void refresh(); // the run may have finished meanwhile: show what it is now
    }
  }

  const { phase, runs } = state;
  const notice = created ? createdNotice(created.number, runs.find((r) => r.run_id === created.id)) : null;
  return (
    <main>
      <h1>Discovery runs</h1>
      <p className="muted">
        Start a filesystem scan or a TLS metadata scan below; both appear here with their reports, and either can also be scheduled to
        repeat on its own. TLS scans are active probes of this machine&apos;s listening ports, not traffic capture. Each finished
        run&apos;s report lists the certificate relationships its evidence supports; a relationship graph is not implemented yet.
      </p>

      <details className="new-scan" open={formOpen} onToggle={(e) => setFormOpen(e.currentTarget.open)}>
        <summary>New scan</summary>
        <NewScanPanel onCreated={onCreated} />
      </details>
      <div role="status" aria-live="polite" className={`notice${notice?.bad ? " notice-bad" : ""}`}>{notice?.text}</div>

      <SchedulesPanel active={active} onRunsChanged={() => void refresh()} />

      <section aria-labelledby="runs-title">
        <div className="toolbar">
          <h2 id="runs-title">Runs</h2>
          <label>
            Status{" "}
            <select value={filters.status ?? ""} onChange={(e) => setFilters((f) => ({ ...f, status: (e.target.value || undefined) as RunStatus | undefined }))}>
              <option value="">All</option>
              {RUN_STATUSES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </label>
          <label>
            Type{" "}
            <select value={filters.type ?? ""} onChange={(e) => setFilters((f) => ({ ...f, type: (e.target.value || undefined) as RunType | undefined }))}>
              <option value="">All</option>
              {RUN_TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </label>
          <button type="button" onClick={() => void refresh()} disabled={state.refreshing || state.loadingMore}>
            {state.refreshing ? "Refreshing…" : "Refresh"}
          </button>
        </div>

        {phase === "loading" && <p role="status">Loading runs&hellip;</p>}
        {phase === "error" && (
          <ErrorPanel onRetry={() => void refresh()} retrying={state.refreshing}>
            {describeError(state.error)}
          </ErrorPanel>
        )}
        {phase === "ready" && state.stale && (
          <ErrorPanel onRetry={() => void refresh()} retrying={state.refreshing}>
            {describeError(state.error)} Showing the last list that loaded; it may be out of date.
          </ErrorPanel>
        )}
        {phase === "ready" && runs.length === 0 && (
          <p className="empty">
            {filters.status || filters.type ? "No runs match these filters." : "No runs yet. Start a scan above."}
          </p>
        )}
        {runs.length > 0 && <RunsTable runs={runs} nowMs={nowMs} actions={actions} onCancel={onCancel} />}
        {phase === "ready" && state.hasMore && (
          <div className="actions">
            <button type="button" onClick={() => void loadMore()} disabled={state.loadingMore || state.refreshing}>
              {state.loadingMore ? "Loading…" : "Load more"}
            </button>
          </div>
        )}
      </section>
    </main>
  );
}
