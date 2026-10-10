import { useState, type FormEvent } from "react";
import { listObservations } from "../../api/client";
import { PARSE_STATUSES, VALIDITY_STATUSES, type Sighting } from "../../api/reportTypes";
import { usePaged } from "../../hooks/useResource";
import { DASH, formatDate, formatDays, formatKey, formatLabel, parseStatusLabel, warningLabel } from "../../format";
import { Loadable } from "./Loadable";
import { Pager } from "./Pager";

export const FILE_PAGE_SIZE = 50;

interface Filters {
  q: string;
  parse_status: string;
  validity_status: string;
}
const NO_FILTERS: Filters = { q: "", parse_status: "", validity_status: "" };

function Result({ row }: { row: Sighting }) {
  return (
    <>
      <div>{parseStatusLabel(row.parse_status)}</div>
      {row.parse_status !== "ok" && row.detail && <div className="muted">{row.detail}</div>}
      {row.access_error && <div className="muted">{row.access_error}</div>}
      {row.warnings.map((warning) => (
        <div key={warning} className="warn-text">{warningLabel(warning)}</div>
      ))}
    </>
  );
}

/** Every file record of ONE run, including the files that held no certificate or could not be read. */
export function FilesTab({ runId, version, emptyText, selected, onOpen }: {
  runId: string;
  version: unknown;
  emptyText: string;
  selected: string | null;
  onOpen: (sha256: string) => void;
}) {
  const [draft, setDraft] = useState<Filters>(NO_FILTERS);
  const [applied, setApplied] = useState<Filters>(NO_FILTERS);
  const filtered = applied.q !== "" || applied.parse_status !== "" || applied.validity_status !== "";

  const list = usePaged(
    ({ offset, frontier }, signal) =>
      listObservations(runId, {
        q: applied.q || undefined,
        parse_status: applied.parse_status || undefined,
        validity_status: applied.validity_status || undefined,
        limit: FILE_PAGE_SIZE,
        offset,
        frontier,
      }, signal),
    `files|${runId}|${JSON.stringify(applied)}`,
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
      <form className="filters" onSubmit={submit} role="search" aria-label="Filter files">
        <label>
          Search{" "}
          <input value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} placeholder="path, subject, issuer" maxLength={200} spellCheck={false} />
        </label>
        <label>
          Result{" "}
          <select value={draft.parse_status} onChange={(e) => setDraft({ ...draft, parse_status: e.target.value })}>
            <option value="">All</option>
            {PARSE_STATUSES.map((s) => (
              <option key={s} value={s}>{parseStatusLabel(s)}</option>
            ))}
          </select>
        </label>
        <label>
          Validity at discovery{" "}
          <select value={draft.validity_status} onChange={(e) => setDraft({ ...draft, validity_status: e.target.value })}>
            <option value="">All</option>
            {VALIDITY_STATUSES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </label>
        <button type="submit">Apply</button>
        {filtered && <button type="button" onClick={clear}>Clear filters</button>}
      </form>

      <Loadable state={list} reload={list.reload} what="files">
        {(page) =>
          page.total === 0 ? (
            <p className="empty">{filtered ? "No files match these filters." : emptyText}</p>
          ) : (
            <>
              <div className="table-wrap">
                <table>
                  <caption className="sr-only">File records of this run, in the order the agent reported them</caption>
                  <thead>
                    <tr>
                      <th scope="col">File</th>
                      <th scope="col">Format</th>
                      <th scope="col">Result</th>
                      <th scope="col">Subject</th>
                      <th scope="col">Issuer</th>
                      <th scope="col">Valid until</th>
                      <th scope="col">Validity at discovery</th>
                      <th scope="col">Key</th>
                      <th scope="col">Duplicate</th>
                    </tr>
                  </thead>
                  <tbody>
                    {page.items.map((row) => (
                      <tr key={row.seq} className={row.sha256 && row.sha256 === selected ? "selected" : undefined}>
                        <th scope="row" className="wrap">
                          <div>{row.filename}</div>
                          <div className="path" title={row.path}>{row.path}</div>
                        </th>
                        <td>{formatLabel(row.format)}</td>
                        <td className="wrap"><Result row={row} /></td>
                        <td className="wrap">
                          {row.sha256 ? (
                            <button type="button" className="link" onClick={() => onOpen(row.sha256!)} aria-expanded={row.sha256 === selected}>
                              {row.subject || DASH}
                            </button>
                          ) : DASH}
                          {row.chain_role && <div className="muted">{row.chain_role.replace("_", "-")}</div>}
                        </td>
                        <td className="wrap">{row.issuer ?? DASH}</td>
                        <td>{formatDate(row.not_after)}</td>
                        <td>
                          {row.validity_status ?? DASH}
                          {row.days_to_expiry !== null && <div className="muted">{formatDays(row.days_to_expiry)}</div>}
                        </td>
                        <td>{formatKey(row.key_algorithm, row.key_size, row.key_curve)}</td>
                        <td>{row.duplicate_kind === "none" ? DASH : row.duplicate_kind === "within_file" ? "Repeated in this file" : "Also in another file"}</td>
                      </tr>
                    ))}
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
