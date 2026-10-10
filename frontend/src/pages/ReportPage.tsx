import { useEffect, useState } from "react";
import { ApiError, getRun, getSummary } from "../api/client";
import { describeError } from "../api/describe";
import { isActive, type Run } from "../api/types";
import { ErrorPanel } from "../components/ErrorPanel";
import { RelationshipsSection } from "../components/RelationshipsSection";
import { StatusBadge } from "../components/StatusBadge";
import { CertificatePanel } from "../components/report/CertificatePanel";
import { CertificatesTab } from "../components/report/CertificatesTab";
import { FilesTab } from "../components/report/FilesTab";
import { IssuesTab } from "../components/report/IssuesTab";
import { Loadable } from "../components/report/Loadable";
import { RunBanner } from "../components/report/RunBanner";
import { SummarySection } from "../components/report/SummarySection";
import { MethodNotice } from "../components/tls/MethodNotice";
import { DASH, describeRunScope, formatDuration, formatTime } from "../format";
import { useResource } from "../hooks/useResource";
import { runsHref } from "../route";
import { TlsReportBody } from "./TlsReport";

type Tab = "certificates" | "files" | "issues";
const TABS: Array<[Tab, string]> = [["certificates", "Certificates"], ["files", "Files"], ["issues", "Issues"]];

function BackLink() {
  return <a className="back" href={runsHref}>&larr; Discovery runs</a>;
}

/**
 * The report of one run: the filesystem report or the TLS probe report, by the run's type. The parent gives this page a `key` of the run id, so opening another run starts from
 * a clean slate: no state of the previous run (tab, page, filters, selected certificate) can leak into the next.
 */
export function ReportPage({ runId }: { runId: string }) {
  const run = useResource((signal) => getRun(runId, signal), [runId], { pollWhile: isActive });
  const [nowMs, setNowMs] = useState(() => Date.now());
  useEffect(() => setNowMs(Date.now()), [run.data]);

  let content;
  if (run.phase === "loading") {
    content = <p role="status">Loading run&hellip;</p>;
  } else if (run.phase === "error" || run.data === null) {
    const missing = run.error instanceof ApiError && run.error.code === "run_not_found";
    content = missing ? (
      <ErrorPanel>That run does not exist (it may belong to a different database).</ErrorPanel>
    ) : (
      <ErrorPanel onRetry={run.reload} retrying={run.reloading}>{describeError(run.error)}</ErrorPanel>
    );
  } else {
    content = (
      <>
        {run.stale && (
          <ErrorPanel onRetry={run.reload} retrying={run.reloading}>
            {describeError(run.error)} Showing the last state that loaded; it may be out of date.
          </ErrorPanel>
        )}
        <ReportForRun run={run.data} nowMs={nowMs} />
      </>
    );
  }

  return (
    <main>
      <BackLink />
      {content}
    </main>
  );
}

function RunHeader({ run }: { run: Run }) {
  const roots = Array.isArray(run.config.roots) ? run.config.roots.filter((r): r is string => typeof r === "string") : null;
  return (
    <header className="report-head">
      <h1>
        Run #{run.run_number} <span className="muted">{run.type === "tls" ? "TLS probe report" : "filesystem report"}</span>
      </h1>
      <p className="mono wrap muted" title="Run id">{run.run_id}</p>
      <dl className="facts inline">
        <dt>Status</dt>
        <dd><StatusBadge status={run.status} cancelRequested={run.cancel_requested} /></dd>
        <dt>Scope</dt>
        <dd className="wrap">
          {run.type === "tls" ? describeRunScope(run) : roots === null ? "Agent default locations" : roots.length === 0 ? DASH : (
            <ul className="plain">
              {roots.map((root) => (
                <li key={root} className="path" title={root}>{root}</li>
              ))}
            </ul>
          )}
        </dd>
        <dt>Queued</dt><dd>{formatTime(run.queued_at)}</dd>
        <dt>Started</dt><dd>{formatTime(run.started_at)}</dd>
        <dt>Finished</dt><dd>{formatTime(run.finished_at)}</dd>
        <dt>Duration</dt><dd>{formatDuration(run.duration_ms)}</dd>
      </dl>
    </header>
  );
}

function emptyTexts(run: Run) {
  if (isActive(run)) {
    const none = "Nothing has been reported yet.";
    return { certificates: none, files: none, issues: "No issues have been recorded so far." };
  }
  if (run.status === "completed") {
    const none = run.record_count === 0
      ? "The agent reported no records for this run, so there is nothing to list."
      : "This run recorded files, but none held a readable certificate. See the Files tab.";
    return { certificates: none, files: run.record_count === 0 ? none : "No file records.", issues: "No issues were recorded for this run." };
  }
  const incomplete = "Nothing was recorded, and this scan did not complete cleanly, so an empty list does not mean there are none.";
  return { certificates: incomplete, files: incomplete, issues: "No individual issues were listed. The reasons for this outcome are in the banner above." };
}

function ReportForRun({ run, nowMs }: { run: Run; nowMs: number }) {
  if (run.type === "tls") {
    return (
      <>
        <RunHeader run={run} />
        <RunBanner run={run} nowMs={nowMs} kind="tls" />
        <MethodNotice />
        {run.status !== "queued" && <TlsReportBody run={run} />}
      </>
    );
  }
  if (run.type !== "filesystem") {
    return (
      <>
        <RunHeader run={run} />
        <ErrorPanel>This page reports filesystem and TLS scans only; it does not know this type of run.</ErrorPanel>
      </>
    );
  }
  return (
    <>
      <RunHeader run={run} />
      <RunBanner run={run} nowMs={nowMs} />
      {run.status !== "queued" && <ReportBody run={run} />}
    </>
  );
}

function ReportBody({ run }: { run: Run }) {
  // Changes whenever the run progressed: the sections look again, keeping what is on screen meanwhile.
  const version = `${run.status}|${run.record_count}|${run.finding_count}|${run.error_count}|${run.rejected_count}|${run.finished_at ?? ""}`;
  const summary = useResource((signal) => getSummary(run.run_id, signal), [run.run_id], { refreshOn: version });
  const [tab, setTab] = useState<Tab>("certificates");
  const [selected, setSelected] = useState<string | null>(null);
  const empty = emptyTexts(run);

  return (
    <>
      <Loadable state={summary} reload={summary.reload} what="summary">
        {(data) => <SummarySection summary={data} />}
      </Loadable>

      <RelationshipsSection runId={run.run_id} version={version} />

      {selected && <CertificatePanel key={selected} runId={run.run_id} sha256={selected} onClose={() => setSelected(null)} />}

      <section aria-label="Findings">
        <div className="tabs" role="tablist" aria-label="Report sections">
          {TABS.map(([id, label]) => (
            <button key={id} type="button" role="tab" id={`tab-${id}`} aria-selected={tab === id} aria-controls={`panel-${id}`} className="tab" onClick={() => setTab(id)}>
              {label}
            </button>
          ))}
        </div>
        <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
          {tab === "certificates" && <CertificatesTab runId={run.run_id} version={version} emptyText={empty.certificates} selected={selected} onOpen={setSelected} />}
          {tab === "files" && <FilesTab runId={run.run_id} version={version} emptyText={empty.files} selected={selected} onOpen={setSelected} />}
          {tab === "issues" && <IssuesTab runId={run.run_id} version={version} emptyText={empty.issues} />}
        </div>
      </section>
    </>
  );
}
