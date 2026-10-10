import { isTlsFinding, outcomeLabel } from "../../format";

/**
 * The result of one probe. A completed handshake is a TLS finding; every other result is said, in words, NOT to be one, so a
 * failed or inconclusive probe cannot be mistaken for a successful TLS service even without colour.
 */
export function OutcomeBadge({ outcome }: { outcome: string }) {
  const finding = isTlsFinding(outcome);
  return (
    <span className="outcome">
      <span className={`badge ${finding ? "badge-completed" : "badge-inconclusive"}`}>{outcomeLabel(outcome)}</span>
      {!finding && <span className="muted"> Not a TLS finding</span>}
    </span>
  );
}
