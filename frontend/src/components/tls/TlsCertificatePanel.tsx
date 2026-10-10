import { getCertificate, listTlsObservations } from "../../api/client";
import { DASH, formatDate, formatKey, outcomeLabel } from "../../format";
import { useResource } from "../../hooks/useResource";
import { Loadable } from "../report/Loadable";

const ROWS_SHOWN = 50;

/**
 * One certificate, as presented in ONE TLS run.
 *
 * The certificate's own facts (subject, SANs, serial, key, dates) come from /api/certificates/{sha256}. That endpoint's sighting
 * and run counts describe FILESYSTEM scans only, so they are deliberately not shown here. Where the certificate was presented comes
 * from THIS run's probe results filtered by its fingerprint. Trust and host names are not evaluated.
 */
export function TlsCertificatePanel({ runId, sha256, onClose }: { runId: string; sha256: string; onClose: () => void }) {
  const detail = useResource((signal) => getCertificate(sha256, signal), [sha256]);
  const here = useResource((signal) => listTlsObservations(runId, { fingerprint: sha256, limit: ROWS_SHOWN }, signal), [runId, sha256]);

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
          </dl>
        )}
      </Loadable>

      <h3>Presented in this run</h3>
      <Loadable state={here} reload={here.reload} what="probe results">
        {(page) => (
          <>
            <p className="hint">
              {page.total === 1 ? "1 probe attempt" : `${page.total} probe attempts`} returned this certificate
              {page.total > page.items.length ? `; the first ${page.items.length} are listed` : ""}. Trust and host names are not evaluated.
            </p>
            <ul className="plain">
              {page.items.map((row) => {
                const position = row.peer_certificates.find((c) => c.sha256 === sha256)?.position ?? 0;
                return (
                  <li key={row.seq} className="wrap">
                    <span className="mono">{row.dst_ip}:{row.dst_port}</span>{" "}
                    <span className="muted">
                      {outcomeLabel(row.handshake_outcome)}
                      {row.tls_version ? `, ${row.tls_version}` : ""}, {position === 0 ? "leaf" : `chain position ${position + 1}`}
                    </span>
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </Loadable>
    </section>
  );
}
