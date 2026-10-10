import type { ReactNode } from "react";

/** An error the user can read and act on. The text is passed as React children (escaped), never as markup. */
export function ErrorPanel({ children, onRetry, retrying = false }: { children: ReactNode; onRetry?: () => void; retrying?: boolean }) {
  return (
    <div className="error-panel" role="alert">
      <span>{children}</span>
      {onRetry && (
        <button type="button" onClick={onRetry} disabled={retrying}>
          {retrying ? "Retrying…" : "Retry"}
        </button>
      )}
    </div>
  );
}
