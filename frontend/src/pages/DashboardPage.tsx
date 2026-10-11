import type { ReactNode } from "react";
import { getDashboard, getRunStatistics, getTlsSummary, listRuns } from "../api/client";
import { describeError } from "../api/describe";
import type { Dashboard, RunStatistics } from "../api/dashboardTypes";
import type { TlsSummary } from "../api/tlsTypes";
import type { Run } from "../api/types";
import { BarChart } from "../components/charts/BarChart";
import {
  cipherRows, expiringOrExpired, finishedRuns, keyAlgorithmRows, runsByStatusAndType, signatureRows, tlsVersionRows, totalRuns, validityRows,
} from "../dashboardData";
import { formatTime } from "../format";
import { useResource, type ResourceState } from "../hooks/useResource";
import { reportHref } from "../route";

interface LatestTls {
  run: Run;
  summary: TlsSummary;
}

/** The newest TLS run that has finished with results (completed or partial), and its summary. There is no aggregate endpoint for TLS. */
async function loadLatestTls(signal: AbortSignal): Promise<LatestTls | null> {
  const runs = await listRuns({ type: "tls", limit: 100 }, signal);
  const run = runs.find((r) => r.status === "completed" || r.status === "partial");
  return run ? { run, summary: await getTlsSummary(run.run_id, signal) } : null;
}

/** One block of the dashboard: its own loading and failure states, so one failing request never blanks the rest. */
function Block<T>({ state, what, children }: { state: ResourceState<T> & { reload: () => void }; what: string; children: (data: T) => ReactNode }) {
  if (state.phase === "loading") return <p role="status">Loading {what}&hellip;</p>;
  if (state.phase === "error" && state.data === null) {
    return (
      <p className="muted">
        Could not load {what} ({describeError(state.error)}){" "}
        <button type="button" onClick={state.reload} disabled={state.reloading}>{state.reloading ? "Retrying…" : "Try again"}</button>
      </p>
    );
  }
  return (
    <>
      {state.stale && <p className="muted">The last refresh failed; showing {what} that loaded before. <button type="button" onClick={state.reload}>Try again</button></p>}
      {children(state.data as T)}
    </>
  );
}

function Tile({ label, value, note }: { label: string; value: ReactNode; note: string }) {
  return (
    <div className="stat">
      <span className="stat-label">{label}</span>
      <strong className="stat-value">{value}</strong>
      <span className="stat-note muted">{note}</span>
    </div>
  );
}

function RunsCharts({ stats }: { stats: RunStatistics }) {
  const { rows, legend, total } = runsByStatusAndType(stats);
  return (
    <BarChart
      title="Runs by status and type"
      subtitle={`All ${total} run${total === 1 ? "" : "s"} recorded, whatever their age.`}
      unit="runs"
      rows={rows}
      legend={legend}
      empty="No run has been recorded yet."
    />
  );
}

function CertificateCharts({ dashboard }: { dashboard: Dashboard }) {
  const run = dashboard.latest_terminal_fs_run;
  const summary = dashboard.summary;
  if (run === null || summary === null) {
    return <p className="empty">No filesystem scan has finished yet, so there are no certificate figures. Run one from the Discovery runs page.</p>;
  }
  const cleanly = run.status === "completed";
  const none = summary.totals.unique_certificates === 0;
  const scope = `Latest finished filesystem run #${run.run_number} (${run.status}), ${summary.totals.unique_certificates} unique certificate${summary.totals.unique_certificates === 1 ? "" : "s"}.`;
  return (
    <>
      <p className="muted">
        {scope} <a href={reportHref(run.run_id)}>Open run #{run.run_number}&apos;s report</a>. These charts describe that one run, not every run.
        {!cleanly && " That run did not complete cleanly, so an empty chart does not mean there are no certificates."}
      </p>
      <div className="chart-grid">
        <BarChart
          title="Certificate validity"
          subtitle={`Unique certificates, judged as of ${formatTime(summary.as_of)}.`}
          unit="certificates"
          rows={validityRows(summary)}
          empty={none ? "No certificate was found in this run." : "No validity figures."}
        />
        <BarChart
          title="Key algorithms"
          subtitle="Unique certificates by public-key algorithm and size or curve, most first."
          unit="certificates"
          rows={keyAlgorithmRows(summary)}
          empty={none ? "No certificate was found in this run." : "No algorithm figures."}
        />
        <BarChart
          title="Signature algorithms"
          subtitle="Unique certificates by signature algorithm, most first."
          unit="certificates"
          rows={signatureRows(summary)}
          empty={none ? "No certificate was found in this run." : "No signature figures."}
        />
      </div>
    </>
  );
}

function TlsCharts({ latest }: { latest: LatestTls | null }) {
  if (latest === null) {
    return <p className="empty">No TLS scan has finished with results yet. Run one from the Discovery runs page; it only probes this machine.</p>;
  }
  const { run, summary } = latest;
  const handshakes = summary.totals.handshakes_completed;
  const cleanly = run.status === "completed";
  return (
    <>
      <p className="muted">
        Latest finished TLS run #{run.run_number} ({run.status}): {handshakes} completed handshake{handshakes === 1 ? "" : "s"} against listeners on this
        machine. <a href={reportHref(run.run_id)}>Open run #{run.run_number}&apos;s report</a>. These are active probe results, not observed traffic, and only completed
        handshakes are counted.
        {!cleanly && " That run did not complete cleanly, so an empty chart does not mean there are no TLS services."}
      </p>
      <div className="chart-grid">
        <BarChart title="TLS versions" subtitle="Completed handshakes by negotiated protocol version." unit="handshakes" rows={tlsVersionRows(summary)} empty="No completed handshake reported a TLS version." />
        <BarChart title="Cipher suites" subtitle="Completed handshakes by negotiated cipher suite, most first." unit="handshakes" rows={cipherRows(summary)} empty="No completed handshake reported a cipher suite." />
      </div>
    </>
  );
}

/**
 * The dashboard: headline figures and charts, all read from existing backend endpoints when the page opens (and on Refresh).
 * Nothing here is computed from anything but those responses, and every chart says which run it describes.
 */
export function DashboardPage() {
  const stats = useResource((signal) => getRunStatistics(signal), []);
  const dashboard = useResource((signal) => getDashboard(signal), []);
  const tls = useResource((signal) => loadLatestTls(signal), []);
  const refreshing = stats.reloading || dashboard.reloading || tls.reloading;
  const refresh = () => {
    stats.reload();
    dashboard.reload();
    tls.reload();
  };

  return (
    <main>
      <div className="toolbar">
        <h1>Dashboard</h1>
        <button type="button" onClick={refresh} disabled={refreshing}>{refreshing ? "Refreshing…" : "Refresh"}</button>
      </div>
      <p className="muted">
        Figures are read from the backend when this page opens and when you press Refresh. Run counts cover every run; certificate charts
        describe the latest finished filesystem run and TLS charts the latest finished TLS run, as each chart states.
      </p>

      <section aria-labelledby="dash-figures">
        <h2 id="dash-figures">Key figures</h2>
        <div className="stats">
          <Block state={stats} what="run counts">
            {(data) => (
              <>
                <Tile label="Runs recorded" value={totalRuns(data)} note="all types and statuses" />
                <Tile label="Runs finished" value={finishedRuns(data)} note="completed, partial or failed" />
              </>
            )}
          </Block>
          <Block state={dashboard} what="certificate figures">
            {(data) =>
              data.summary && data.latest_terminal_fs_run ? (
                <>
                  <Tile label="Unique certificates" value={data.summary.totals.unique_certificates} note={`latest filesystem run #${data.latest_terminal_fs_run.run_number}`} />
                  <Tile label="Expiring or expired" value={expiringOrExpired(data.summary)} note={`of those, within ${data.summary.expiring_days.value} days or past`} />
                </>
              ) : (
                <Tile label="Unique certificates" value="—" note="no filesystem scan has finished" />
              )
            }
          </Block>
          <Block state={tls} what="TLS figures">
            {(data) => <Tile label="TLS handshakes completed" value={data ? data.summary.totals.handshakes_completed : "—"} note={data ? `latest TLS run #${data.run.run_number}` : "no TLS scan has finished"} />}
          </Block>
        </div>
      </section>

      <section aria-labelledby="dash-runs">
        <h2 id="dash-runs">Runs</h2>
        <Block state={stats} what="the run counts">{(data) => <RunsCharts stats={data} />}</Block>
      </section>

      <section aria-labelledby="dash-certs">
        <h2 id="dash-certs">Certificates found in files</h2>
        <Block state={dashboard} what="the certificate charts">{(data) => <CertificateCharts dashboard={data} />}</Block>
      </section>

      <section aria-labelledby="dash-tls">
        <h2 id="dash-tls">TLS probes of this machine</h2>
        <Block state={tls} what="the TLS charts">{(data) => <TlsCharts latest={data} />}</Block>
      </section>
    </main>
  );
}
