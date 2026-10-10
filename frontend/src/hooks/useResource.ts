// Load one thing from the API with abort, retry, optional polling, and a strict rule about identity:
//
//  * `deps` say WHAT is being shown (a run, a page, a filter). When they change the old data is dropped at once - the very
//    next render already reports "loading", never the previous run's rows - the old request is aborted, and an answer that
//    arrives late for the old deps is ignored;
//  * `refreshOn` says WHEN to look again without changing what is shown (the run progressed): the current data stays on
//    screen while the refresh is running, and a failed refresh keeps it, marked stale;
//  * polling runs only while `pollWhile(data)` is true and the tab is visible; it resumes at once when the tab comes back.
import { useCallback, useEffect, useRef, useState } from "react";
import { isAbortError } from "../api/client";

export const REPORT_POLL_MS = 3000;
export const REPORT_POLL_AFTER_ERROR_MS = 10_000;

export interface ResourceState<T> {
  phase: "loading" | "ready" | "error";
  data: T | null;
  error: unknown;
  stale: boolean; // a refresh failed; `data` is the last good answer
  reloading: boolean;
}

interface Stored<T> extends ResourceState<T> {
  key: string;
}

const LOADING = { phase: "loading", data: null, error: null, stale: false, reloading: false } as const;

export interface ResourceOptions<T> {
  pollWhile?: (data: T) => boolean;
  refreshOn?: unknown;
}

export function useResource<T>(load: (signal: AbortSignal) => Promise<T>, deps: readonly unknown[], options: ResourceOptions<T> = {}) {
  const key = JSON.stringify(deps);
  const [stored, setStored] = useState<Stored<T>>({ key, ...LOADING });
  const loadRef = useRef(load);
  loadRef.current = load;
  const keyRef = useRef(key);
  keyRef.current = key;
  const generation = useRef(0);
  const controllerRef = useRef<AbortController | null>(null);
  const failedRef = useRef(false);

  const fetchNow = useCallback(async (): Promise<void> => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const mine = ++generation.current;
    const forKey = keyRef.current;
    setStored((s) => (s.key === forKey ? { ...s, reloading: true } : s));
    try {
      const data = await loadRef.current(controller.signal);
      if (mine !== generation.current) return;
      failedRef.current = false;
      setStored({ key: forKey, phase: "ready", data, error: null, stale: false, reloading: false });
    } catch (error) {
      if (mine !== generation.current || controller.signal.aborted || isAbortError(error)) return;
      failedRef.current = true;
      setStored((s) =>
        s.key === forKey && s.data !== null
          ? { ...s, stale: true, error, reloading: false }
          : { key: forKey, phase: "error", data: null, error, stale: false, reloading: false },
      );
    }
  }, []);

  // A different subject: start over.
  useEffect(() => {
    failedRef.current = false;
    setStored({ key, ...LOADING });
    void fetchNow();
    return () => {
      generation.current += 1; // anything still in flight is now obsolete
      controllerRef.current?.abort();
    };
  }, [key, fetchNow]);

  // The same subject has progressed: look again, keeping what is on screen.
  const lastRefresh = useRef(options.refreshOn);
  useEffect(() => {
    if (Object.is(lastRefresh.current, options.refreshOn)) return;
    lastRefresh.current = options.refreshOn;
    void fetchNow();
  }, [options.refreshOn, fetchNow]);

  const view: ResourceState<T> = stored.key === key ? stored : { ...LOADING };
  const polling = view.data !== null && options.pollWhile !== undefined && options.pollWhile(view.data);

  useEffect(() => {
    if (!polling) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let running = false;
    const schedule = () => {
      timer = setTimeout(tick, failedRef.current ? REPORT_POLL_AFTER_ERROR_MS : REPORT_POLL_MS);
    };
    const tick = async () => {
      timer = undefined;
      if (stopped || document.hidden) return; // hidden: paused until the tab is visible again
      running = true;
      await fetchNow();
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
  }, [polling, fetchNow]);

  return { ...view, reload: fetchNow };
}

export interface PageInfo {
  frontier: number;
  total: number;
  limit: number;
  offset: number;
}

interface PagerState {
  key: string;
  offset: number;
  pin: number | undefined;
}

/**
 * A paged list. `resetKey` identifies the filters and the run: when it changes the list goes back to the first page.
 * Moving to a later page pins the `frontier` the first page reported, so the pages all describe the same moment even while
 * the run is still adding records; refreshes of page 1 are not pinned and so pick up new data.
 */
export function usePaged<T extends PageInfo>(
  load: (query: { offset: number; frontier: number | undefined }, signal: AbortSignal) => Promise<T>,
  resetKey: string,
  options: ResourceOptions<T> = {},
) {
  const [state, setState] = useState<PagerState>({ key: resetKey, offset: 0, pin: undefined });
  const current = state.key === resetKey ? state : { key: resetKey, offset: 0, pin: undefined };
  const resource = useResource<T>((signal) => load({ offset: current.offset, frontier: current.pin }, signal), [resetKey, current.offset, current.pin], options);

  const goTo = (offset: number) => {
    const pin = offset === 0 ? undefined : (current.pin ?? resource.data?.frontier);
    setState({ key: resetKey, offset: Math.max(0, offset), pin });
  };
  return { ...resource, offset: current.offset, goTo };
}
