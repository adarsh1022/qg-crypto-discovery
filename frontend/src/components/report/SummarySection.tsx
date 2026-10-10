import type { Summary, ValidityCounts } from "../../api/reportTypes";
import { formatTime, parseStatusLabel } from "../../format";

function Stat({ label, value, hint }: { label: string; value: number; hint?: string }) {
  return (
    <div className="stat" title={hint}>
      <dt>{label}</dt>
      <dd>{value.toLocaleString()}</dd>
    </div>
  );
}

function Validity({ title, counts, note }: { title: string; counts: ValidityCounts; note?: string }) {
  return (
    <div className="validity">
      <h3>{title}</h3>
      <dl className="stats compact">
        <Stat label="Valid" value={counts.valid} />
        <Stat label="Expiring" value={counts.expiring} />
        <Stat label="Expired" value={counts.expired} />
        <Stat label="Not yet valid" value={counts.not_yet_valid} />
      </dl>
      {note && <p className="hint">{note}</p>}
    </div>
  );
}

export function SummarySection({ summary }: { summary: Summary }) {
  const { totals, issues, validity } = summary;
  const statuses = Object.entries(summary.parse_status).filter(([, count]) => count > 0);
  const issueTotal = issues.errors.total + issues.rejected + issues.seq_conflicts;
  return (
    <section aria-labelledby="summary-title">
      <h2 id="summary-title">Summary</h2>
      <p className="hint">As of {formatTime(summary.as_of)}.</p>
      <dl className="stats">
        <Stat label="Records" value={totals.records} hint="Observation records the agent reported; a file holding several certificates gives several records" />
        <Stat label="Certificate sightings" value={totals.sightings} hint="Records that carry a certificate; the same certificate in two files counts twice" />
        <Stat label="Unique certificates" value={totals.unique_certificates} />
        <Stat label="Duplicate sightings" value={totals.duplicate_observations.total} hint="Sightings of a certificate that was already seen in this run" />
        <Stat label="Files without a certificate" value={totals.no_certificate} />
        <Stat label="Files not read or parsed" value={totals.parse_failures} hint="Malformed, unsupported, too large, access denied or read errors" />
        <Stat label="Skipped" value={totals.skipped} />
        <Stat label="Issues recorded" value={issueTotal} hint="Scan errors, rejected records and upload conflicts" />
      </dl>

      <div className="validity-grid">
        <Validity
          title="Unique certificates now"
          counts={validity.now.unique}
          note={`Judged against today's date. "Expiring" means within ${summary.expiring_days.value} days.`}
        />
        <Validity title="Sightings at discovery" counts={validity.at_discovery} note="Judged as of when each file was scanned." />
      </div>

      {statuses.length > 0 && (
        <p className="hint">
          Records by result: {statuses.map(([status, count]) => `${parseStatusLabel(status)} ${count}`).join(", ")}.
        </p>
      )}
    </section>
  );
}
