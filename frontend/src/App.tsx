import { ErrorPanel } from "./components/ErrorPanel";
import { ReportPage } from "./pages/ReportPage";
import { RunsPage } from "./pages/RunsPage";
import { runsHref, useRoute } from "./route";

export function App() {
  const route = useRoute();
  const onRuns = route.name === "runs";
  return (
    <>
      <header className="app-header">
        <strong>Certificate discovery</strong>
        <nav aria-label="Main">
          <a href={runsHref} aria-current={onRuns ? "page" : undefined}>Discovery runs</a>
        </nav>
      </header>
      {/* The list stays mounted while a report is open, so its filters, loaded pages and cancel state are still there when
          the user comes back; it does not poll while hidden. */}
      <div hidden={!onRuns}>
        <RunsPage active={onRuns} />
      </div>
      {route.name === "report" && <ReportPage key={route.runId} runId={route.runId} />}
      {route.name === "invalid" && (
        <main>
          <a className="back" href={runsHref}>&larr; Discovery runs</a>
          <ErrorPanel>That is not a valid run link.</ErrorPanel>
        </main>
      )}
    </>
  );
}
