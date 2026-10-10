import { useState } from "react";
import { getTlsSummary } from "../api/client";
import { isActive, type Run } from "../api/types";
import type { TlsSummary } from "../api/tlsTypes";
import { RelationshipsSection } from "../components/RelationshipsSection";
import { Loadable } from "../components/report/Loadable";
import { ObservationsTab } from "../components/tls/ObservationsTab";
import { TlsCertificatePanel } from "../components/tls/TlsCertificatePanel";
import { TlsIssuesTab } from "../components/tls/TlsIssuesTab";
import { TlsSummarySection } from "../components/tls/TlsSummarySection";
import { useResource } from "../hooks/useResource";

type Tab = "results" | "issues";
const TABS: Array<[Tab, string]> = [["results", "Probe results"], ["issues", "Issues"]];

/**
 * What to say when a list is empty. It never claims that no TLS service exists: an empty list means "no probe results were
 * recorded", and for a failed or partial run it says the scan did not complete cleanly.
 */
export function tlsEmptyTexts(run: Run, scan: TlsSummary["scan"]) {
  if (isActive(run)) return { results: "No probe results have been reported yet.", issues: "No issues have been recorded so far." };
  if (run.status === "completed") {
    let none = "The agent reported no probe results for this run.";
    if (scan?.enumeration === "ok" && scan.listeners_found === 0) none = "The agent found no listening TCP sockets on this machine, so there was nothing to probe.";
    else if (scan?.enumeration === "ok" && (scan.listeners_found ?? 0) > 0 && scan.targets_planned === 0) {
      none = `The agent found ${scan.listeners_found} listening socket${scan.listeners_found === 1 ? "" : "s"}, but none was eligible to probe (skipped by policy: ${scan.policy_skipped ?? 0}, left out by the port list: ${scan.port_filtered ?? 0}).`;
    }
    return { results: none, issues: "No issues were recorded for this run." };
  }
  const incomplete = "Nothing was recorded, and this scan did not complete cleanly, so an empty list does not mean there are no TLS services.";
  return { results: incomplete, issues: "No individual issues were listed. The reasons for this outcome are in the banner above." };
}

/** The data part of a TLS run's report: summary, tabs, certificate panel. Every request is for this run only. */
export function TlsReportBody({ run }: { run: Run }) {
  // Changes whenever the run progressed: the sections look again, keeping what is on screen meanwhile.
  const version = `${run.status}|${run.record_count}|${run.finding_count}|${run.error_count}|${run.rejected_count}|${run.finished_at ?? ""}`;
  const summary = useResource((signal) => getTlsSummary(run.run_id, signal), [run.run_id], { refreshOn: version });
  const [tab, setTab] = useState<Tab>("results");
  const [selected, setSelected] = useState<string | null>(null);
  const empty = tlsEmptyTexts(run, summary.data?.scan ?? null);

  return (
    <>
      <Loadable state={summary} reload={summary.reload} what="summary">
        {(data) => <TlsSummarySection summary={data} />}
      </Loadable>

      <RelationshipsSection runId={run.run_id} version={version} />

      {selected && <TlsCertificatePanel key={selected} runId={run.run_id} sha256={selected} onClose={() => setSelected(null)} />}

      <section aria-label="Probe results and issues">
        <div className="tabs" role="tablist" aria-label="Report sections">
          {TABS.map(([id, label]) => (
            <button key={id} type="button" role="tab" id={`tls-tab-${id}`} aria-selected={tab === id} aria-controls={`tls-panel-${id}`} className="tab" onClick={() => setTab(id)}>
              {label}
            </button>
          ))}
        </div>
        <div role="tabpanel" id={`tls-panel-${tab}`} aria-labelledby={`tls-tab-${tab}`}>
          {tab === "results" && <ObservationsTab runId={run.run_id} version={version} emptyText={empty.results} selected={selected} onOpen={setSelected} />}
          {tab === "issues" && <TlsIssuesTab runId={run.run_id} version={version} emptyText={empty.issues} />}
        </div>
      </section>
    </>
  );
}
