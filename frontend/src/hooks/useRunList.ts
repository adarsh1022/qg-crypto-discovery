// The run list: loading, refresh, "load more" and polling.
//
// Polling rules:
//  * it runs only while at least one listed run is queued or running, and only while the tab is visible;
//    when the tab becomes visible again it refreshes at once;
//  * one list request is in flight at a time; a poll that finds one still running is skipped;
//  * a request whose filters were changed (or whose page was left) is aborted, and its answer is ignored;
//  * after a failed refresh the last good list stays on screen, marked stale, and polling slows down.
import { useCallback, useEffect, useRef, useState } from "react";
import { isAbortError, listRuns } from "../api/client";
import { isActive, type Run, type RunFilters } from "../api/types";

export const PAGE_SIZE = 50;
export const POLL_MS = 3000;
export const POLL_AFTER_ERROR_MS = 10_000;
const MAX_LIMIT = 1000; // the backend's largest page

export type ListPhase = "loading" | "ready" | "error";

export interface RunListState {
  phase: ListPhase;
  runs: Run[];
  hasMore: boolean;
  error: unknown;
  stale: boolean; // a refresh failed; `runs` is the last good answer
  loadingMore: boolean;
  refreshing: boolean;
}

const INITIAL: RunListState = { phase: "loading", runs: [], hasMore: false, error: null, stale: false, loadingMore: false, refreshing: false };

export function useRunList(filters: RunFilters, enabled = true) {
  const [state, setState] = useState<RunListState>(INITIAL);
  const runsRef = useRef<Run[]>([]);
  const controllerRef = useRef<AbortController | null>(null);
  const inFlightRef = useRef(false);
  const failedRef = useRef(false);
  const filtersKey = `${filters.type ?? ""}|${filters.status ?? ""}`;

  const apply = useCallback((patch: Partial<RunListState>) => {
    if (patch.runs) runsRef.current = patch.runs;
    setState((s) => ({ ...s, ...patch }));
  }, []);

  /** Re-read the loaded part of the list from the start (so rows that changed state, and new runs, show up). */
  const refresh = useCallback(async (): Promise<void> => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    const controller = new AbortController();
    controllerRef.current = controller;
    const limit = Math.min(MAX_LIMIT, Math.max(PAGE_SIZE, runsRef.current.length));
    setState((s) => ({ ...s, refreshing: true }));
    try {
      const runs = await listRuns({ ...filters, limit }, controller.signal);
      failedRef.current = false;
      apply({ phase: "ready", runs, hasMore: runs.length >= limit, error: null, stale: false, refreshing: false });
    } catch (error) {
      if (isAbortError(error) || controller.signal.aborted) return;
      failedRef.current = true;
      setState((s) => (s.phase === "ready" ? { ...s, stale: true, error, refreshing: false } : { ...s, phase: "error", error, refreshing: false }));
    } finally {
      if (controllerRef.current === controller) {
        controllerRef.current = null;
        inFlightRef.current = false;
      }
    }
  }, [filtersKey, apply]);

  const loadMore = useCallback(async (): Promise<void> => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    const controller = new AbortController();
    controllerRef.current = controller;
    setState((s) => ({ ...s, loadingMore: true }));
    try {
      const offset = runsRef.current.length;
      const more = await listRuns({ ...filters, limit: PAGE_SIZE, offset }, controller.signal);
      const known = new Set(runsRef.current.map((r) => r.run_id)); // a new run can shift rows between pages
      apply({ runs: [...runsRef.current, ...more.filter((r) => !known.has(r.run_id))], hasMore: more.length >= PAGE_SIZE, loadingMore: false, stale: false, error: null });
    } catch (error) {
      if (isAbortError(error) || controller.signal.aborted) return;
      setState((s) => ({ ...s, loadingMore: false, stale: true, error }));
    } finally {
      if (controllerRef.current === controller) {
        controllerRef.current = null;
        inFlightRef.current = false;
      }
    }
  }, [filtersKey, apply]);

  /** Put one run (for example the answer to a cancel request) into the list without another round trip. */
  const replaceRun = useCallback((run: Run) => {
    apply({ runs: runsRef.current.map((r) => (r.run_id === run.run_id ? run : r)) });
  }, [apply]);

  // First load, and a fresh start whenever the filters change.
  useEffect(() => {
    controllerRef.current?.abort();
    controllerRef.current = null;
    inFlightRef.current = false;
    failedRef.current = false;
    runsRef.current = [];
    setState(INITIAL);
    void refresh();
    return () => {
      controllerRef.current?.abort();
      controllerRef.current = null;
      inFlightRef.current = false;
    };
  }, [refresh]);

  const anyActive = state.runs.some(isActive) && enabled; // not while the page is hidden behind a report

  // Coming back to the list: look again at once, because runs may have changed while it was hidden.
  const wasEnabled = useRef(enabled);
  useEffect(() => {
    if (enabled && !wasEnabled.current) void refresh();
    wasEnabled.current = enabled;
  }, [enabled, refresh]);

  // Polling.
  useEffect(() => {
    if (!anyActive) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let running = false; // a poll is in flight

    const schedule = () => {
      timer = setTimeout(tick, failedRef.current ? POLL_AFTER_ERROR_MS : POLL_MS);
    };
    const tick = async () => {
      timer = undefined;
      if (stopped || document.hidden) return; // hidden: the chain pauses until the tab is visible again
      running = true;
      await refresh();
      running = false;
      if (!stopped) schedule();
    };
    const onVisible = () => {
      if (stopped || document.hidden || running || timer !== undefined) return;
      void tick();
    };

    schedule();
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      stopped = true;
      if (timer !== undefined) clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [anyActive, refresh]);

  return { state, refresh, loadMore, replaceRun };
}
