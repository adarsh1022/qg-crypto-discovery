import { useState, type FormEvent } from "react";
import { createRun } from "../api/client";
import { describeError, offendingField } from "../api/describe";
import type { Run } from "../api/types";
import {
  buildTlsConfig,
  EMPTY_TLS_FORM,
  TLS_MAX_BUDGET_SECONDS,
  TLS_MAX_PORTS,
  TLS_MAX_TARGETS,
  TLS_MAX_TIMEOUT_SECONDS,
  type TlsFormErrors,
  type TlsFormValues,
} from "../scanForm";
import { ErrorPanel } from "./ErrorPanel";

const KNOWN_FIELDS = ["ports", "max_targets", "connect_timeout_seconds", "handshake_timeout_seconds", "time_budget_seconds"] as const;

/**
 * Start a TLS metadata scan. The agent probes TLS listeners on THIS machine: its targets always come from the operating system's
 * table of listening sockets, so there is deliberately no field for a host or an address. A port list can only narrow that table.
 * With no ports the form refuses to submit unless the user ticks the explicit opt-in to probe every eligible listener.
 */
export function NewTlsScanForm({ onCreated }: { onCreated: (run: Run) => void }) {
  const [values, setValues] = useState<TlsFormValues>(EMPTY_TLS_FORM);
  const [errors, setErrors] = useState<TlsFormErrors>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const set = <K extends keyof TlsFormValues>(key: K, value: TlsFormValues[K]) => setValues((v) => ({ ...v, [key]: value }));

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (submitting) return;
    const { config, errors: found } = buildTlsConfig(values);
    setErrors(found);
    setFailure(null);
    if (!config) return;
    setSubmitting(true);
    try {
      const run = await createRun({ type: "tls", config });
      setValues(EMPTY_TLS_FORM);
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
  const number = (id: string, label: string, hint: string, key: "maxTargets" | "connectTimeoutSeconds" | "handshakeTimeoutSeconds" | "timeBudgetSeconds", error: string | undefined) =>
    field(
      id,
      label,
      hint,
      error,
      <input
        id={id}
        inputMode="decimal"
        value={values[key]}
        disabled={submitting}
        onChange={(e) => set(key, e.target.value)}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(id, true, error)}
      />,
    );

  return (
    <form className="card" onSubmit={submit} noValidate aria-labelledby="new-tls-scan-title">
      <h2 id="new-tls-scan-title">TLS scan settings</h2>
      <p className="hint">
        The agent makes a TLS handshake attempt against listening TCP services on this machine (the agent must be running). It cannot
        be pointed at another host: its targets always come from the operating system&apos;s list of listening sockets on this machine.
      </p>
      <p className="hint" id="tls-method-hint">
        This is an active probe, not traffic capture. It sends a TLS ClientHello to each listener and no application data; services
        that are not TLS may log the attempt. Direction is unknown and packet counts are unavailable.
      </p>

      {field(
        "tls-ports",
        "Ports to probe",
        `Whole numbers from 1 to 65535, separated by spaces or commas (at most ${TLS_MAX_PORTS}). Only listeners that are actually open on this machine are probed; a port nothing listens on is ignored.`,
        errors.ports,
        <input
          id="tls-ports"
          value={values.ports}
          disabled={values.probeAll || submitting}
          onChange={(e) => set("ports", e.target.value)}
          aria-invalid={errors.ports ? true : undefined}
          aria-describedby={describedBy("tls-ports", true, errors.ports)}
          spellCheck={false}
        />,
      )}

      <div className="field checkbox">
        <input
          id="tls-all"
          type="checkbox"
          checked={values.probeAll}
          disabled={submitting}
          onChange={(e) => set("probeAll", e.target.checked)}
          aria-describedby="tls-all-hint"
        />
        <label htmlFor="tls-all">Probe every eligible TLS listener on this machine</label>
        <p className="hint warn-text" id="tls-all-hint">
          Broad: probes every listening TCP socket the operating system reports that passes the target policy (wildcard listeners are
          reached through loopback), up to 128 targets unless you raise the limit. Leave this unticked and list ports to keep the scan narrow.
        </p>
      </div>

      <details>
        <summary>Advanced TLS options</summary>
        {number("tls-targets", "Maximum targets", `Default 128, at most ${TLS_MAX_TARGETS}.`, "maxTargets", errors.max_targets)}
        {number("tls-connect", "Connect timeout (seconds)", `Default 2, above 0 and at most ${TLS_MAX_TIMEOUT_SECONDS}.`, "connectTimeoutSeconds", errors.connect_timeout_seconds)}
        {number("tls-handshake", "Handshake timeout (seconds)", `Default 3, above 0 and at most ${TLS_MAX_TIMEOUT_SECONDS}.`, "handshakeTimeoutSeconds", errors.handshake_timeout_seconds)}
        {number("tls-budget", "Time budget (seconds)", `Default 60, above 0 and at most ${TLS_MAX_BUDGET_SECONDS}. The scan stops, and the run is marked partial, when this runs out.`, "timeBudgetSeconds", errors.time_budget_seconds)}
      </details>

      {failure && <ErrorPanel>{failure}</ErrorPanel>}
      <div className="actions">
        <button type="submit" className="primary" disabled={submitting}>
          {submitting ? "Starting…" : "Run TLS metadata scan"}
        </button>
      </div>
    </form>
  );
}
