import type { ReactNode } from "react";
import { describeError } from "../../api/describe";
import type { ResourceState } from "../../hooks/useResource";
import { ErrorPanel } from "../ErrorPanel";

/** The three states every report section has: loading, a failure with Retry, and the data (marked when it is stale). */
export function Loadable<T>({ state, reload, what, children }: {
  state: ResourceState<T>;
  reload: () => void;
  what: string;
  children: (data: T) => ReactNode;
}) {
  if (state.phase === "loading") return <p role="status">Loading {what}&hellip;</p>;
  if (state.phase === "error" || state.data === null) {
    return (
      <ErrorPanel onRetry={reload} retrying={state.reloading}>
        {describeError(state.error)}
      </ErrorPanel>
    );
  }
  return (
    <>
      {state.stale && (
        <ErrorPanel onRetry={reload} retrying={state.reloading}>
          {describeError(state.error)} Showing the last {what} that loaded; it may be out of date.
        </ErrorPanel>
      )}
      {children(state.data)}
    </>
  );
}
