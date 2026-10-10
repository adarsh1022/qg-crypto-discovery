import { listIssues } from "../../api/client";
import { usePaged } from "../../hooks/useResource";
import { DASH } from "../../format";
import { Loadable } from "./Loadable";
import { Pager } from "./Pager";

export const ISSUE_PAGE_SIZE = 50;

/** Errors the agent recorded and records the backend refused, for ONE run. */
export function IssuesTab({ runId, version, emptyText }: { runId: string; version: unknown; emptyText: string }) {
  const list = usePaged(
    ({ offset }, signal) => listIssues(runId, { limit: ISSUE_PAGE_SIZE, offset }, signal).then((page) => ({ ...page, frontier: 0 })),
    `issues|${runId}`,
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
                <caption className="sr-only">Issues recorded for this run</caption>
                <thead>
                  <tr>
                    <th scope="col">Reported by</th>
                    <th scope="col">Kind</th>
                    <th scope="col">Code</th>
                    <th scope="col">Path</th>
                    <th scope="col" className="num">Record #</th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((issue, index) => (
                    <tr key={`${page.offset + index}`}>
                      <th scope="row">{issue.source}</th>
                      <td>{issue.kind}</td>
                      <td className="wrap">{issue.code}</td>
                      <td className="wrap">{issue.path ? <span className="path" title={issue.path}>{issue.path}</span> : DASH}</td>
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
