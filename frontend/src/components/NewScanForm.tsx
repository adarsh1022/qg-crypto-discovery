import { useState, type FormEvent } from "react";
import { createRun } from "../api/client";
import { describeError, offendingField } from "../api/describe";
import type { Run } from "../api/types";
import { buildConfig, EMPTY_FORM, type FormErrors, type ScanFormValues } from "../scanForm";
import { ErrorPanel } from "./ErrorPanel";

const KNOWN_FIELDS = ["roots", "extensions", "exclude_paths", "max_depth", "time_budget_seconds", "expiring_days"] as const;

export function NewScanForm({ onCreated }: { onCreated: (run: Run) => void }) {
  const [values, setValues] = useState<ScanFormValues>(EMPTY_FORM);
  const [errors, setErrors] = useState<FormErrors>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const set = <K extends keyof ScanFormValues>(key: K, value: ScanFormValues[K]) => setValues((v) => ({ ...v, [key]: value }));

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (submitting) return;
    const { config, errors: found } = buildConfig(values);
    setErrors(found);
    setFailure(null);
    if (!config) return;
    setSubmitting(true);
    try {
      const run = await createRun({ type: "filesystem", config });
      setValues(EMPTY_FORM);
      onCreated(run);
    } catch (error) {
      const field = offendingField(error);
      if (field && (KNOWN_FIELDS as readonly string[]).includes(field)) {
        setErrors({ [field]: "The backend did not accept this value." });
      } else {
        setFailure(describeError(error));
      }
    } finally {
      setSubmitting(false);
    }
  }

  const field = (id: string, label: string, hint: string | null, error: string | undefined, control: JSX.Element) => (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {control}
      {hint && <p className="hint" id={`${id}-hint`}>{hint}</p>}
      {error && <p className="field-error" id={`${id}-error`} role="alert">{error}</p>}
    </div>
  );
  const describedBy = (id: string, hint: boolean, error: string | undefined) =>
    [hint ? `${id}-hint` : null, error ? `${id}-error` : null].filter(Boolean).join(" ") || undefined;

  return (
    <form className="card" onSubmit={submit} noValidate aria-labelledby="new-scan-title">
      <h2 id="new-scan-title">Scan settings</h2>
      <p className="hint">The agent scans the folders below for certificate files (it must be running: <code>python -m agent</code>).</p>

      {field(
        "scan-roots",
        "Folders to scan (one per line)",
        "Absolute local paths, for example C:\\Users\\you\\certs",
        errors.roots,
        <textarea
          id="scan-roots"
          rows={3}
          value={values.roots}
          disabled={values.useDefaultLocations || submitting}
          onChange={(e) => set("roots", e.target.value)}
          aria-invalid={errors.roots ? true : undefined}
          aria-describedby={describedBy("scan-roots", true, errors.roots)}
          spellCheck={false}
        />,
      )}

      <div className="field checkbox">
        <input
          id="scan-defaults"
          type="checkbox"
          checked={values.useDefaultLocations}
          disabled={submitting}
          onChange={(e) => set("useDefaultLocations", e.target.checked)}
          aria-describedby="scan-defaults-hint"
        />
        <label htmlFor="scan-defaults">Use the agent's default locations instead</label>
        <p className="hint" id="scan-defaults-hint">
          Broad: the agent's Downloads, Documents and Desktop folders, ~/.aspnet/https, ProgramData and Program Files\Git (those that exist). This can take
          several minutes.
        </p>
      </div>

      <details>
        <summary>Advanced options</summary>
        {field(
          "scan-extensions",
          "File extensions",
          "Leave empty for the defaults: .pem .crt .cer .cert .der .pfx .p12",
          errors.extensions,
          <input
            id="scan-extensions"
            value={values.extensions}
            disabled={submitting}
            onChange={(e) => set("extensions", e.target.value)}
            aria-invalid={errors.extensions ? true : undefined}
            aria-describedby={describedBy("scan-extensions", true, errors.extensions)}
            spellCheck={false}
          />,
        )}
        {field(
          "scan-exclude",
          "Paths to skip (one per line)",
          "Absolute paths.",
          errors.exclude_paths,
          <textarea
            id="scan-exclude"
            rows={2}
            value={values.excludePaths}
            disabled={submitting}
            onChange={(e) => set("excludePaths", e.target.value)}
            aria-invalid={errors.exclude_paths ? true : undefined}
            aria-describedby={describedBy("scan-exclude", true, errors.exclude_paths)}
            spellCheck={false}
          />,
        )}
        {field(
          "scan-depth",
          "Maximum folder depth",
          "Default 12.",
          errors.max_depth,
          <input
            id="scan-depth"
            inputMode="numeric"
            value={values.maxDepth}
            disabled={submitting}
            onChange={(e) => set("maxDepth", e.target.value)}
            aria-invalid={errors.max_depth ? true : undefined}
            aria-describedby={describedBy("scan-depth", true, errors.max_depth)}
          />,
        )}
        {field(
          "scan-budget",
          "Time budget (seconds)",
          "Default 600. The scan stops, and the run is marked partial, when this runs out.",
          errors.time_budget_seconds,
          <input
            id="scan-budget"
            inputMode="numeric"
            value={values.timeBudgetSeconds}
            disabled={submitting}
            onChange={(e) => set("timeBudgetSeconds", e.target.value)}
            aria-invalid={errors.time_budget_seconds ? true : undefined}
            aria-describedby={describedBy("scan-budget", true, errors.time_budget_seconds)}
          />,
        )}
        {field(
          "scan-expiring",
          "\u201CExpiring soon\u201D window (days)",
          "Default 30.",
          errors.expiring_days,
          <input
            id="scan-expiring"
            inputMode="numeric"
            value={values.expiringDays}
            disabled={submitting}
            onChange={(e) => set("expiringDays", e.target.value)}
            aria-invalid={errors.expiring_days ? true : undefined}
            aria-describedby={describedBy("scan-expiring", true, errors.expiring_days)}
          />,
        )}
      </details>

      {failure && <ErrorPanel>{failure}</ErrorPanel>}
      <div className="actions">
        <button type="submit" className="primary" disabled={submitting}>
          {submitting ? "Starting\u2026" : "Run filesystem scan"}
        </button>
      </div>
    </form>
  );
}
