import { useState, type FormEvent } from "react";
import { listTlsObservations } from "../../api/client";
import { ATTRIBUTIONS, TLS_OUTCOMES, TLS_VERSIONS, type TlsObservation } from "../../api/tlsTypes";
import { DASH, attributionLabel, formatDate, formatKey, formatTime, outcomeLabel, probeWarnings, shortHash, warningLabel } from "../../format";
import { usePaged } from "../../hooks/useResource";
import { Loadable } from "../report/Loadable";
import { Pager } from "../report/Pager";
import { OutcomeBadge } from "./OutcomeBadge";

export const OBSERVATION_PAGE_SIZE = 50;

interface Filters {
  q: string;
  outcome: string;
  tls_version: string;
  process_attribution: string;
}
const NO_FILTERS: Filters = { q: "", outcome: "", tls_version: "", process_attribution: "" };

function Process({ row }: { row: TlsObservation }) {
  if (row.process_attribution === "attributed") {
    return (
      <span title={row.exe_path ?? undefined}>
        {row.process_name} <span className="muted">(PID {row.pid})</span>
      </span>
    );
  }
  return (
    <span className="muted" title={row.pid !== null ? `PID ${row.pid}` : undefined}>
      {attributionLabel(row.process_attribution)}
      {row.pid !== null && ` (PID ${row.pid})`}
    </span>
  );
}

function Details({ row }: { row: TlsObservation }) {
  return (
    <details className="row-details">
      <summary>Details</summary>
      <dl className="facts">
        <dt>Probe</dt>
        <dd>
          Active probe attempt #{row.seq + 1} at {formatTime(row.observed_at)}; direction {row.direction}; {row.transport.toUpperCase()}
        </dd>
        <dt>Sockets</dt>
        <dd className="mono wrap">
          probe socket {row.src_ip}:{row.src_port} &rarr; listener {row.dst_ip}:{row.dst_port}
        </dd>
        <dt>Counts</dt>
        <dd>
          {row.event_count} probe attempt{row.event_count === 1 ? "" : "s"}; packet count {row.packet_count} (unavailable: no packet capture)
        </dd>
        <dt>Process</dt>
        <dd className="wrap">
          {attributionLabel(row.process_attribution)}
          {row.pid !== null && `, PID ${row.pid}`}
          {row.exe_path && (
            <>
              <br />
              <span className="path" title={row.exe_path}>{row.exe_path}</span>
            </>
          )}
        </dd>
        <dt>Server name (SNI)</dt>
        <dd>{row.sni ?? "None sent (the probe connects to an IP address)"}</dd>
        <dt>Certificate visibility</dt>
        <dd>{row.cert_visibility === "visible" ? "Certificate facts were read from the handshake" : "No certificate was read"}</dd>
        <dt>Evidence</dt>
        <dd>
          {row.evidence_confidence} confidence
          {row.warnings.length > 0 && (
            <ul className="plain">
              {row.warnings.map((w) => (
                <li key={w} className="wrap">{warningLabel(w)}</li>
              ))}
            </ul>
          )}
        </dd>
        {row.peer_certificates.length > 0 && (
          <>
            <dt>Chain</dt>
            <dd>
              <ol className="chain">
                {row.peer_certificates.map((c) => (
                  <li key={c.position} className="wrap">
                    {c.position === 0 ? "Leaf" : `#${c.position + 1}`}: {c.subject} <span className="mono" title={c.sha256}>{shortHash(c.sha256)}</span>
                  </li>
                ))}
              </ol>
            </dd>
          </>
        )}
      </dl>
    </details>
  );
}

/** Every probe attempt of ONE run. A completed handshake is a TLS finding; every other result says it is not. */
export function ObservationsTab({ runId, version, emptyText, selected, onOpen }: {
  runId: string;
  version: unknown;
  emptyText: string;
  selected: string | null;
  onOpen: (sha256: string) => void;
}) {
  const [draft, setDraft] = useState<Filters>(NO_FILTERS);
  const [applied, setApplied] = useState<Filters>(NO_FILTERS);
  const filtered = Object.values(applied).some((v) => v !== "");

  const list = usePaged(
    ({ offset, frontier }, signal) =>
      listTlsObservations(runId, {
        q: applied.q || undefined,
        outcome: applied.outcome || undefined,
        tls_version: applied.tls_version || undefined,
        process_attribution: applied.process_attribution || undefined,
        limit: OBSERVATION_PAGE_SIZE,
        offset,
        frontier,
      }, signal),
    `tls|${runId}|${JSON.stringify(applied)}`,
    { refreshOn: version },
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setApplied({ ...draft, q: draft.q.trim() });
  };
  const clear = () => {
    setDraft(NO_FILTERS);
    setApplied(NO_FILTERS);
  };

  return (
    <>
      <form className="filters" onSubmit={submit} role="search" aria-label="Filter probe results">
        <label>
          Search{" "}
          <input value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} placeholder="address, process, subject" maxLength={200} spellCheck={false} />
        </label>
        <label>
          Result{" "}
          <select value={draft.outcome} onChange={(e) => setDraft({ ...draft, outcome: e.target.value })}>
            <option value="">All</option>
            {TLS_OUTCOMES.map((o) => (
              <option key={o} value={o}>{outcomeLabel(o)}</option>
            ))}
          </select>
        </label>
        <label>
          TLS version{" "}
          <select value={draft.tls_version} onChange={(e) => setDraft({ ...draft, tls_version: e.target.value })}>
            <option value="">All</option>
            {TLS_VERSIONS.map((v) => (
              <option key={v} value={v}>{v}</option>
            ))}
          </select>
        </label>
        <label>
          Process{" "}
          <select value={draft.process_attribution} onChange={(e) => setDraft({ ...draft, process_attribution: e.target.value })}>
            <option value="">All</option>
            {ATTRIBUTIONS.map((a) => (
              <option key={a} value={a}>{attributionLabel(a)}</option>
            ))}
          </select>
        </label>
        <button type="submit">Apply</button>
        {filtered && <button type="button" onClick={clear}>Clear filters</button>}
      </form>

      <Loadable state={list} reload={list.reload} what="probe results">
        {(page) =>
          page.total === 0 ? (
            <p className="empty">{filtered ? "No probe results match these filters." : emptyText}</p>
          ) : (
            <>
              <div className="table-wrap">
                <table>
                  <caption className="sr-only">Active probe attempts of this run, in the order the agent reported them</caption>
                  <thead>
                    <tr>
                      <th scope="col">Result</th>
                      <th scope="col">Listener probed</th>
                      <th scope="col">TLS version and cipher</th>
                      <th scope="col">Leaf certificate</th>
                      <th scope="col">Process</th>
                      <th scope="col">Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {page.items.map((row) => {
                      const leaf = row.peer_certificates[0];
                      const extras = probeWarnings(row.warnings);
                      return (
                        <tr key={row.seq} className={leaf && leaf.sha256 === selected ? "selected" : undefined}>
                          <th scope="row" className="wrap">
                            <OutcomeBadge outcome={row.handshake_outcome} />
                          </th>
                          <td className="mono wrap">{row.dst_ip}:{row.dst_port}</td>
                          <td className="wrap">
                            {row.tls_version ? (
                              <>
                                {row.tls_version}
                                <div className="muted">{row.cipher_suite ?? DASH}</div>
                              </>
                            ) : DASH}
                          </td>
                          <td className="wrap">
                            {leaf ? (
                              <>
                                <button type="button" className="link" onClick={() => onOpen(leaf.sha256)} aria-expanded={leaf.sha256 === selected}>
                                  {leaf.subject || DASH}
                                </button>
                                <div className="muted">
                                  <span className="mono" title={leaf.sha256}>{shortHash(leaf.sha256)}</span> &middot; until {formatDate(leaf.not_after)} &middot;{" "}
                                  {formatKey(leaf.key_algorithm, leaf.key_size, leaf.key_curve)}
                                  {row.peer_certificates.length > 1 && ` · +${row.peer_certificates.length - 1} in chain`}
                                </div>
                              </>
                            ) : DASH}
                          </td>
                          <td className="wrap"><Process row={row} /></td>
                          <td className="wrap">
                            <div>{row.evidence_confidence} confidence</div>
                            {extras.map((w) => (
                              <div key={w} className="warn-text">{warningLabel(w)}</div>
                            ))}
                            <Details row={row} />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <Pager offset={page.offset} limit={page.limit} total={page.total} busy={list.reloading} onPage={list.goTo} />
            </>
          )
        }
      </Loadable>
    </>
  );
}
