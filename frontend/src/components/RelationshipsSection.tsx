import { getRelationships } from "../api/client";
import { describeError } from "../api/describe";
import type { Relationship, RelationshipPage } from "../api/relationshipTypes";
import { formatTime, shortHash } from "../format";
import { useResource } from "../hooks/useResource";
import { reportHref } from "../route";

/** What the recording status means, in words that never turn "not recorded" into "none exist". */
export function recordingMessage(page: RelationshipPage) {
  const { state, expected, missing, unexpected } = page.recording;
  const kind = page.run.type;
  const caveat = page.run.status === "completed" ? "" : " This run did not complete cleanly, so the absence of a relationship does not mean there is none.";
  switch (state) {
    case "pending":
      return { headline: "Not recorded yet.", detail: "Relationships are recorded when the run finishes; nothing is recorded for a run that is still queued or running." };
    case "recorded":
      return { headline: `${page.total} relationship${page.total === 1 ? "" : "s"} recorded for this run.`, detail: caveat.trim() };
    case "none_expected":
      return {
        headline: "No relationships expected.",
        detail: (kind === "tls"
          ? "No completed handshake in this run returned a certificate, so there is nothing to relate, and nothing was recorded."
          : "No certificate was successfully parsed from a file in this run (or the run had no host), so there is nothing to relate, and nothing was recorded.") + caveat,
      };
    default:
      if (page.recording.recorded === 0 && unexpected === 0) {
        return {
          headline: "Not recorded for this run.",
          detail: `This run's stored evidence supports ${expected} relationship${expected === 1 ? "" : "s"}, but none was stored for it. That is expected for runs made before relationship recording existed; it can also mean recording failed when the run finished. Nothing has been inferred or filled in.`,
        };
      }
      return {
        headline: "Only partly recorded for this run.",
        detail: `${missing} of ${expected} relationship${expected === 1 ? "" : "s"} supported by this run's evidence ${missing === 1 ? "is" : "are"} missing or differ${unexpected ? `, and ${unexpected} stored ${unexpected === 1 ? "is" : "are"} not supported by it` : ""}. What is listed is stored data and may be incomplete.`,
      };
  }
}

function FromCell({ row }: { row: Relationship }) {
  const node = row.source;
  if (node.kind === "endpoint") {
    const host = node.host;
    return (
      <>
        <strong>Local listener</strong> <span className="mono wrap">{node.label}</span>
        <div className="muted wrap">on host {host?.hostname ?? "unknown"} <span className="mono">({host?.host_id})</span></div>
      </>
    );
  }
  return (
    <>
      <span className="wrap">{node.label}</span>
      {node.sha256 && <div className="mono muted" title={node.sha256}>{shortHash(node.sha256)}</div>}
    </>
  );
}

function ToCell({ row }: { row: Relationship }) {
  const node = row.target;
  if (node.kind === "host") {
    return (
      <>
        <strong>Host</strong> <span className="wrap">{node.label}</span>
        <div className="mono muted">{node.host_id}</div>
      </>
    );
  }
  return (
    <>
      <span className="wrap">{node.label}</span>
      {node.sha256 && <div className="mono muted" title={node.sha256}>{shortHash(node.sha256)}</div>}
    </>
  );
}

function FilesystemEvidence({ row }: { row: Relationship }) {
  const evidence = row.filesystem_evidence;
  if (!evidence) return null;
  if (evidence.hosts.length === 0) return <span className="muted">Not found in any filesystem scan.</span>;
  return (
    <>
      <ul className="plain">
        {evidence.hosts.map((host) => (
          <li key={host.host_id} className="wrap">
            File with the same fingerprint on {host.hostname} <span className="mono muted">({host.host_id})</span>: {host.observations} sighting{host.observations === 1 ? "" : "s"} in {host.runs} run{host.runs === 1 ? "" : "s"}
            {host.latest_run_id && host.latest_run_number !== null && (
              <>, latest <a href={reportHref(host.latest_run_id)}>run #{host.latest_run_number}</a></>
            )}
            <span className="muted"> (last seen {formatTime(host.last_seen_at)})</span>
          </li>
        ))}
      </ul>
      {evidence.omitted > 0 && <div className="muted">and {evidence.omitted} more host{evidence.omitted === 1 ? "" : "s"} not shown.</div>}
    </>
  );
}

function Table({ page }: { page: RelationshipPage }) {
  const tls = page.run.type === "tls";
  return (
    <div className="table-wrap">
      <table>
        <caption className="sr-only">Relationships recorded for run #{page.run.run_number}</caption>
        <thead>
          <tr>
            <th scope="col">Relationship</th>
            <th scope="col">From</th>
            <th scope="col">To</th>
            <th scope="col">In this run</th>
            <th scope="col">Across runs</th>
            {tls && <th scope="col">Listening process</th>}
            {tls && <th scope="col">Same certificate in files (separate evidence)</th>}
          </tr>
        </thead>
        <tbody>
          {page.items.map((row) => (
            <tr key={`${row.kind}|${row.source.sha256 ?? row.source.label}|${row.source.host?.host_id ?? ""}|${row.target.sha256 ?? row.target.host_id}`}>
              <th scope="row" className="wrap">{row.label}</th>
              <td className="wrap"><FromCell row={row} /></td>
              <td className="wrap"><ToCell row={row} /></td>
              <td>
                {row.in_run.observations} observation{row.in_run.observations === 1 ? "" : "s"}
                <div className="muted">last {formatTime(row.in_run.last_at)}</div>
              </td>
              <td>
                {row.all_runs.observations} in {row.all_runs.runs} run{row.all_runs.runs === 1 ? "" : "s"}
                <div className="muted">{formatTime(row.all_runs.first_seen_at)} &ndash; {formatTime(row.all_runs.last_seen_at)}</div>
              </td>
              {tls && (
                <td className="wrap">
                  {row.process ? (
                    <>
                      {row.process.name}
                      {row.process.exe_path && <div className="mono muted wrap">{row.process.exe_path}</div>}
                    </>
                  ) : (
                    <span className="muted">Not determined</span>
                  )}
                </td>
              )}
              {tls && <td className="wrap"><FilesystemEvidence row={row} /></td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * The relationships a finished run recorded. Honest about its limits: a TLS row is a certificate returned by a COMPLETED active
 * probe of a listener on this machine (not observed traffic); a filesystem row is a certificate parsed from a file (not proof of
 * use). A run that predates recording says "Not recorded for this run", which is different from "No relationships expected".
 */
export function RelationshipsSection({ runId, version }: { runId: string; version: string }) {
  const state = useResource((signal) => getRelationships(runId, signal), [runId], { refreshOn: version });
  const page = state.data;

  let body;
  if (state.phase === "loading") {
    body = <p role="status">Loading relationships&hellip;</p>;
  } else if (page === null) {
    // quiet: the rest of the report is unaffected, so this is not an alert
    body = (
      <p className="muted">
        Could not load the relationships ({describeError(state.error)}){" "}
        <button type="button" onClick={state.reload} disabled={state.reloading}>{state.reloading ? "Retrying…" : "Try again"}</button>
      </p>
    );
  } else {
    const message = recordingMessage(page);
    const tls = page.run.type === "tls";
    body = (
      <>
        {state.stale && <p className="muted">The last refresh failed; showing the relationships that loaded before. <button type="button" onClick={state.reload}>Try again</button></p>}
        <p><strong>{message.headline}</strong> {message.detail}</p>
        <p className="hint">
          {tls
            ? "Each row is a certificate returned by a completed TLS handshake, which the agent attempted itself against a listener on this machine. This is an active probe, not observed traffic: there is no remote peer, direction or packet count. A listening process is shown only when every completed probe of that listener was attributed to the same one."
            : "Each row is a certificate parsed from a file on the host that ran the scan. It shows the file exists there, not that the certificate is in use."}
        </p>
        {page.items.length > 0 && <Table page={page} />}
        {page.truncated && <p className="muted">Showing the first {page.items.length} of {page.total} relationships.</p>}
      </>
    );
  }

  return (
    <section aria-labelledby="relationships-title">
      <h2 id="relationships-title">Relationships</h2>
      {body}
    </section>
  );
}
