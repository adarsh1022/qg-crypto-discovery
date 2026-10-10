/**
 * The always-visible statement of what TLS report data is. It is deliberately prominent and is not dismissable: every number and
 * row below describes active probe attempts, never observed network traffic and never certificate trust.
 */
export function MethodNotice() {
  return (
    <aside className="method-notice" aria-label="How this TLS data was collected">
      <strong>Active local probe results, not observed traffic.</strong>
      <ul>
        <li>
          Each row is <strong>one probe attempt</strong>: the agent connected to a TLS listener on this machine and tried a handshake.
          Nothing was captured from other applications' connections.
        </li>
        <li>
          Direction is <strong>unknown</strong>. Packet counts are <strong>unavailable</strong> because packet capture is disabled; the
          counts shown are probe attempts, not packets.
        </li>
        <li>
          Only a <strong>completed handshake</strong> is a TLS finding. A failed, incomplete or alert result is evidence of an
          inconclusive probe, and a service that does not answer as TLS is not reported as a TLS service.
        </li>
        <li>Certificates are shown as facts only. Trust, certificate chains to a root, and host names are <strong>not evaluated</strong>.</li>
      </ul>
    </aside>
  );
}
