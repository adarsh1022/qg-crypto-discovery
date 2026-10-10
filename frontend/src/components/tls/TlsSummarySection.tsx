import type { TlsSummary } from "../../api/tlsTypes";
import { attributionLabel, formatTime, outcomeLabel } from "../../format";

function Stat({ label, value, hint, tone }: { label: string; value: number; hint?: string; tone?: "ok" | "warn" }) {
  return (
    <div className={`stat${tone ? ` stat-${tone}` : ""}`} title={hint}>
      <dt>{label}</dt>
      <dd>{value.toLocaleString()}</dd>
    </div>
  );
}

function Counts({ title, entries }: { title: string; entries: Array<[string, number]> }) {
  const shown = entries.filter(([, count]) => count > 0);
  return (
    <div className="counts">
      <h3>{title}</h3>
      {shown.length === 0 ? (
        <p className="hint">None.</p>
      ) : (
        <ul className="plain">
          {shown.map(([label, count]) => (
            <li key={label}>
              {label} <strong>{count}</strong>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** What the agent says it did, as stored with the run. A failed enumeration is called out; "no listeners" is not a failure. */
function ScanCoverage({ scan }: { scan: NonNullable<TlsSummary["scan"]> }) {
  const failed = scan.enumeration === "failed";
  return (
    <p className={failed ? "field-error" : "hint"} role={failed ? "alert" : undefined}>
      {failed
        ? "The agent could not read the operating system's list of listening sockets, so nothing was probed. "
        : "The agent read the operating system's list of listening sockets. "}
      {!failed && scan.listeners_found !== null && `Listeners found: ${scan.listeners_found}. `}
      {!failed && scan.policy_skipped ? `Skipped by the local-target policy: ${scan.policy_skipped}. ` : ""}
      {!failed && scan.port_filtered ? `Left out by the run's port list: ${scan.port_filtered}. ` : ""}
      {!failed && scan.targets_planned !== null && `Probe targets: ${scan.targets_planned}. `}
      {!failed && scan.targets_probed !== null && `Probed: ${scan.targets_probed}. `}
      {scan.targets_truncated ? "The target limit was reached, so not every listener was probed. " : ""}
      {!failed && scan.stop_reason && scan.stop_reason !== "completed" ? `The scan stopped early (${scan.stop_reason}).` : ""}
    </p>
  );
}

export function TlsSummarySection({ summary }: { summary: TlsSummary }) {
  const { totals, issues, certificate_validity: validity } = summary;
  return (
    <section aria-labelledby="tls-summary-title">
      <h2 id="tls-summary-title">Summary</h2>
      <p className="hint">As of {formatTime(summary.as_of)}.</p>
      <dl className="stats">
        <Stat label="Probe attempts" value={totals.probe_attempts} hint="Probes that produced a result. One probe attempt per row; these are not packets." />
        <Stat label="Completed TLS handshakes" value={totals.handshakes_completed} tone="ok" hint="The only TLS findings" />
        <Stat label="Failed or inconclusive probes" value={totals.not_completed} tone={totals.not_completed ? "warn" : undefined}
              hint="Failed, incomplete, alert or unknown results. These are NOT TLS findings." />
        <Stat label="Endpoints probed" value={totals.endpoints} hint="Distinct listener address and port pairs" />
        <Stat label="Certificates presented" value={totals.certificates_presented} hint="Distinct certificates presented by completed handshakes" />
        <Stat label="Leaf certificates" value={totals.leaf_certificates} />
        <Stat label="Scan errors" value={issues.errors.total} hint="Errors the agent reported (a failed enumeration, a probe that could not be made)" />
        <Stat label="Rejected records" value={issues.rejected} hint="Records the backend refused" />
      </dl>

      {summary.scan && <ScanCoverage scan={summary.scan} />}

      <div className="validity-grid">
        <Counts title="Probe outcomes" entries={Object.entries(summary.outcomes).map(([k, v]) => [outcomeLabel(k), v])} />
        <Counts title="TLS versions (completed handshakes)" entries={Object.entries(summary.tls_versions)} />
        <Counts
          title="Cipher suites (completed handshakes)"
          entries={[
            ...summary.cipher_suites.top.map((c): [string, number] => [c.cipher_suite ?? "unknown", c.handshakes]),
            ...(summary.cipher_suites.other ? ([[`${summary.cipher_suites.other.groups} other`, summary.cipher_suites.other.handshakes]] as Array<[string, number]>) : []),
          ]}
        />
        <Counts title="Process attribution" entries={Object.entries(summary.process_attribution).map(([k, v]) => [attributionLabel(k), v])} />
      </div>

      <div className="validity">
        <h3>Leaf certificates now</h3>
        <dl className="stats compact">
          <Stat label="Valid" value={validity.now.valid} />
          <Stat label="Expiring" value={validity.now.expiring} />
          <Stat label="Expired" value={validity.now.expired} />
          <Stat label="Not yet valid" value={validity.now.not_yet_valid} />
        </dl>
        <p className="hint">
          Judged against today's date; &quot;expiring&quot; means within {validity.expiring_days.value} days. This is the dates only: trust and
          host names are not evaluated.
        </p>
      </div>
    </section>
  );
}
