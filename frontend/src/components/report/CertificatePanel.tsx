import { getCertificate, listObservations } from "../../api/client";
import { useResource } from "../../hooks/useResource";
import { DASH, formatDate, formatKey, formatLabel } from "../../format";
import { Loadable } from "./Loadable";

const PATHS_SHOWN = 50;

/**
 * One certificate, as seen by ONE run.
 *
 * The certificate's own facts (subject, SANs, serial, key, dates) come from /api/certificates/{sha256}, which describes the
 * certificate independent of any run. Where it was found comes from the observations of THIS run filtered by its
 * fingerprint, so no path from another run can appear here. Other runs are only counted, never listed.
 */
export function CertificatePanel({ runId, sha256, onClose }: { runId: string; sha256: string; onClose: () => void }) {
  const detail = useResource((signal) => getCertificate(sha256, signal), [sha256]);
  const here = useResource((signal) => listObservations(runId, { fingerprint: sha256, limit: PATHS_SHOWN }, signal), [runId, sha256]);

  return (
    <section className="panel" aria-label="Certificate details">
      <div className="panel-head">
        <h2>Certificate</h2>
        <button type="button" onClick={onClose}>Close</button>
      </div>
      <Loadable state={detail} reload={detail.reload} what="certificate details">
        {(cert) => (
          <dl className="facts">
            <dt>Subject</dt><dd className="wrap">{cert.subject || DASH}</dd>
            <dt>Issuer</dt><dd className="wrap">{cert.issuer || DASH}</dd>
            <dt>Serial number</dt><dd className="mono wrap">{cert.serial_hex || DASH}</dd>
            <dt>SHA-256</dt><dd className="mono wrap">{cert.sha256}</dd>
            <dt>Valid</dt><dd>{formatDate(cert.not_before)} to {formatDate(cert.not_after)}</dd>
            <dt>Public key</dt><dd>{formatKey(cert.key_algorithm, cert.key_size, cert.key_curve)}</dd>
            <dt>Signature</dt><dd>{cert.signature_algorithm || DASH}</dd>
            <dt>Certificate authority</dt><dd>{cert.is_ca === null ? "Not recorded" : cert.is_ca ? "Yes" : "No"}</dd>
            <dt>Subject alternative names</dt>
            <dd>
              {cert.san.length === 0 ? (
                "None recorded"
              ) : (
                <ul className="plain">
                  {cert.san.map((entry, index) => (
                    <li key={index} className="wrap">
                      <span className="muted">{entry.type}</span> {entry.value}
                    </li>
                  ))}
                </ul>
              )}
            </dd>
            <dt>Other runs</dt>
            <dd>{cert.runs_total > 1 ? `Also seen in ${cert.runs_total - 1} other ${cert.runs_total === 2 ? "run" : "runs"}` : "Not seen in any other run"}</dd>
          </dl>
        )}
      </Loadable>

      <h3>Found in this run</h3>
      <Loadable state={here} reload={here.reload} what="locations">
        {(page) => (
          <>
            <p className="hint">
              {page.total === 1 ? "1 sighting" : `${page.total} sightings`}
              {page.total > page.items.length ? `; the first ${page.items.length} are listed` : ""}.
            </p>
            <ul className="plain">
              {page.items.map((row) => (
                <li key={row.seq}>
                  <span className="path" title={row.path}>{row.path}</span>
                  <span className="muted"> {formatLabel(row.format)}{row.chain_total && row.chain_total > 1 ? `, #${(row.chain_index ?? 0) + 1} of ${row.chain_total} in the chain` : ""}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </Loadable>
    </section>
  );
}
