// A minimal hash router: two views, no dependency, no server fallback needed.
//   #/runs            the Discovery Runs list (also the default)
//   #/runs/<run_id>   the report of that run (filesystem or TLS)
//   #/dashboard       headline figures and charts
import { useEffect, useState } from "react";

export type Route = { name: "runs" } | { name: "dashboard" } | { name: "report"; runId: string } | { name: "invalid" };

const RUN_ID = /^[0-9a-f]{32}$/;

export const runsHref = "#/runs";
export const dashboardHref = "#/dashboard";
export const reportHref = (runId: string) => `#/runs/${runId}`;

export function parseHash(hash: string): Route {
  const path = hash.replace(/^#\/?/, "").replace(/\/+$/, "");
  if (path === "" || path === "runs") return { name: "runs" };
  if (path === "dashboard") return { name: "dashboard" };
  const match = /^runs\/(.+)$/.exec(path);
  if (match && RUN_ID.test(match[1])) return { name: "report", runId: match[1] };
  return { name: "invalid" };
}

export function useRoute(): Route {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onChange = () => setHash(window.location.hash);
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return parseHash(hash);
}
