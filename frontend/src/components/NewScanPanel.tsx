import { useState } from "react";
import type { Run } from "../api/types";
import { NewScanForm } from "./NewScanForm";
import { NewTlsScanForm } from "./NewTlsScanForm";

type Kind = "filesystem" | "tls";
const TABS: Array<[Kind, string]> = [["filesystem", "Filesystem scan"], ["tls", "TLS metadata scan"]];

/**
 * The two ways to start a run. Both forms stay mounted and only the selected one is shown, so text typed into one is not lost
 * when the user looks at the other.
 */
export function NewScanPanel({ onCreated }: { onCreated: (run: Run) => void }) {
  const [kind, setKind] = useState<Kind>("filesystem");
  return (
    <>
      <div className="tabs" role="tablist" aria-label="Scan type">
        {TABS.map(([id, label]) => (
          <button key={id} type="button" role="tab" id={`scan-tab-${id}`} aria-selected={kind === id} aria-controls={`scan-panel-${id}`} className="tab" onClick={() => setKind(id)}>
            {label}
          </button>
        ))}
      </div>
      <div role="tabpanel" id="scan-panel-filesystem" aria-labelledby="scan-tab-filesystem" hidden={kind !== "filesystem"}>
        <NewScanForm onCreated={onCreated} />
      </div>
      <div role="tabpanel" id="scan-panel-tls" aria-labelledby="scan-tab-tls" hidden={kind !== "tls"}>
        <NewTlsScanForm onCreated={onCreated} />
      </div>
    </>
  );
}
