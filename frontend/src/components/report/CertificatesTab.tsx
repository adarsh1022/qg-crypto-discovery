import { listCertificates } from "../../api/client";
import { usePaged } from "../../hooks/useResource";
import { DASH, formatDate, formatKey, shortHash } from "../../format";
import { Loadable } from "./Loadable";
import { Pager } from "./Pager";

export const CERT_PAGE_SIZE = 50;

/** The unique certificates of ONE run, soonest expiry first. */
export function CertificatesTab({ runId, version, emptyText, selected, onOpen }: {
  runId: string;
  version: unknown;
  emptyText: string;
  selected: string | null;
  onOpen: (sha256: string) => void;
}) {
  const list = usePaged(
    ({ offset, frontier }, signal) => listCertificates(runId, { sort: "not_after", direction: "asc", limit: CERT_PAGE_SIZE, offset, frontier }, signal),
    `certificates|${runId}`,
    { refreshOn: version },
  );
  return (
    <Loadable state={list} reload={list.reload} what="certificates">
      {(page) =>
        page.items.length === 0 && page.total === 0 ? (
          <p className="empty">{emptyText}</p>
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <caption className="sr-only">Unique certificates found in this run, soonest expiry first</caption>
                <thead>
                  <tr>
                    <th scope="col">Subject</th>
                    <th scope="col">Issuer</th>
                    <th scope="col">Valid from</th>
                    <th scope="col">Valid until</th>
                    <th scope="col">Key</th>
                    <th scope="col">Signature</th>
                    <th scope="col" className="num" title="Times this certificate was seen in this run">Sightings</th>
                    <th scope="col" className="num" title="Distinct file paths it was seen at in this run">Files</th>
                    <th scope="col">SHA-256</th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((cert) => (
                    <tr key={cert.sha256} className={cert.sha256 === selected ? "selected" : undefined}>
                      <th scope="row" className="wrap">
                        <button type="button" className="link" onClick={() => onOpen(cert.sha256)} aria-expanded={cert.sha256 === selected}>
                          {cert.subject || DASH}
                        </button>
                      </th>
                      <td className="wrap">{cert.issuer || DASH}</td>
                      <td>{formatDate(cert.not_before)}</td>
                      <td>{formatDate(cert.not_after)}</td>
                      <td>{formatKey(cert.key_algorithm, cert.key_size, cert.key_curve)}</td>
                      <td className="wrap">{cert.signature_algorithm || DASH}</td>
                      <td className="num">{cert.sightings}</td>
                      <td className="num">{cert.paths}</td>
                      <td className="mono" title={cert.sha256}>{shortHash(cert.sha256)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager offset={page.offset} limit={page.limit} total={page.total} busy={list.reloading} onPage={list.goTo} />
          </>
        )
      }
    </Loadable>
  );
}
