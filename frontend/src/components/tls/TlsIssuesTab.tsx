import { listTlsIssues } from "../../api/client";
import { usePaged } from "../../hooks/useResource";
import { Loadable } from "../report/Loadable";
import { Pager } from "../report/Pager";
import { DASH } from "../../format";

export const TLS_ISSUE_PAGE_SIZE = 50;

/** Scan errors the agent recorded and records the backend refused, for ONE TLS run. */
export function TlsIssuesTab({ runId, version, emptyText }: { runId: string; version: unknown; emptyText: string }) {
  const list = usePaged(
    ({ offset }, signal) => listTlsIssues(runId, { limit: TLS_ISSUE_PAGE_SIZE, offset }, signal).then((page) => ({ ...page, frontier: 0 })),
    `tls-issues|${runId}`,
    { refreshOn: version },
  );
  return (
    <Loadable state={list} reload={list.reload} what="issues">
      {(page) =>
        page.total === 0 ? (
          <p className="empty">{emptyText}</p>
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <caption className="sr-only">Issues recorded for this TLS run</caption>
                <thead>
                  <tr>
                    <th scope="col">Reported by</th>
                    <th scope="col">Kind</th>
                    <th scope="col">Code</th>
                    <th scope="col" className="num">Record #</th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((issue, index) => (
                    <tr key={page.offset + index}>
                      <th scope="row">{issue.source}</th>
                      <td>{issue.kind}</td>
                      <td className="wrap">{issue.code}</td>
                      <td className="num">{issue.seq ?? DASH}</td>
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
  );
}
