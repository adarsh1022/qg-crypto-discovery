"""Builders for TLS ingestion tests: valid probe records, peer certificate facts, scan summaries and running tls runs."""
import copy
import datetime as dt

from backend import db, runs, tls_ingest

NOW = dt.datetime(2026, 3, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
STAMP = "2026-03-01T12:00:00Z"
MARKERS = ["active_probe", "packet_counts_unavailable"]


def at(seconds):
    return NOW + dt.timedelta(seconds=seconds)


def sha(n: int) -> str:
    return f"{n:064x}"


def peer(n=1, **overrides) -> dict:
    """Certificate facts as the agent sends them. The same `n` always means the same certificate."""
    facts = dict(sha256=sha(n), serial_hex=f"{n:x}", subject=f"CN=cert{n}", issuer="CN=Test CA",
                 san=[{"type": "dns", "value": f"host{n}.example"}], key_algorithm="RSA", key_size=2048, key_curve=None,
                 signature_algorithm="sha256WithRSAEncryption", not_before="2025-01-01T00:00:00Z",
                 not_after="2027-01-01T00:00:00Z", is_ca=False)
    facts.update(overrides)
    return facts


def tls_record(n=1, *, port=8443, peers=None, **overrides) -> dict:
    """A valid COMPLETED probe record of a listener on 127.0.0.1:`port`, presenting certificate `n`."""
    peers = [peer(n)] if peers is None else peers
    record = dict(
        observed_at=STAMP, direction="unknown", transport="tcp", src_ip="127.0.0.1", src_port=50000 + n, dst_ip="127.0.0.1",
        dst_port=port, handshake_outcome="completed", sni=None, tls_version="TLS1.3", cipher_suite="TLS_AES_256_GCM_SHA384",
        cert_visibility="visible" if peers else "not_observed", pid=4321, process_name="svc.exe", exe_path="C:\\svc\\svc.exe",
        process_attribution="attributed", event_count=1, packet_count=0,
        event_counts={"probe_attempts": 1, "handshake_completed": 1}, evidence_confidence="high",
        warnings=list(MARKERS), peer_certificates=peers)
    record.update(overrides)
    return record


def failed_record(port=9000, outcome="failed", code="handshake_failed", **overrides) -> dict:
    """A valid probe record that is NOT a TLS finding: an inconclusive or failed handshake, no version, cipher or certificate."""
    record = tls_record(port=port, peers=[], handshake_outcome=outcome, tls_version=None, cipher_suite=None,
                        cert_visibility="not_observed", evidence_confidence="low", warnings=MARKERS + [code], pid=None,
                        process_name=None, exe_path=None, process_attribution="unavailable",
                        event_counts={"probe_attempts": 1, "handshake_completed": 0})
    record.update(overrides)
    return record


def tls_summary(records: int, *, completed=None, stop_reason="completed", enumeration="ok", errors=(), errors_total=None,
                **extra) -> dict:
    listed = [dict(e) if isinstance(e, dict) else e for e in errors]
    out = dict(stop_reason=stop_reason, complete=stop_reason == "completed", enumeration=enumeration, listeners_found=records,
               port_filtered=0, policy_skipped=0, targets_planned=records, targets_probed=records, records=records,
               handshakes_completed=records if completed is None else completed, targets_truncated=False,
               records_by_outcome={}, errors=listed, errors_total=len(listed) if errors_total is None else errors_total,
               elapsed_seconds=1.5)
    out.update(extra)
    return out


def tls_error(kind="probe", code="target_not_local") -> dict:
    return dict(kind=kind, code=code)


def deep(value):
    return copy.deepcopy(value)


def running_tls_run(conn, *, config=None) -> str:
    run_id = runs.create_run(conn, "tls", "manual", now=NOW, config=config)
    runs.start_run(conn, run_id, now=at(1))
    return run_id


def ingest(conn, run_id, records, *, start=0, now=None):
    items = list(enumerate(records, start))
    with db.transaction(conn):
        return tls_ingest.ingest_tls_batch_in_tx(conn, run_id, items, now=now or at(2))


def finish(conn, run_id, records_count=None, **kwargs):
    if "summary" not in kwargs and records_count is not None:
        kwargs["summary"] = tls_summary(records_count)
    with db.transaction(conn):
        return tls_ingest.finalize_tls_run_in_tx(conn, run_id, now=at(10), **kwargs)


# ------------------------------------------------------------------ a varied dataset for the TLS report tests
def build_tls_records() -> list[dict]:
    """Ten probe records (seq 0..9): six completed handshakes (one chain of three, one certificate seen twice, one TLS 1.2,
    three leaf certificates with different validity) and four probes that are NOT findings (failed, incomplete, alert, unknown)."""
    chain = [peer(1), peer(2, is_ca=True), peer(3, is_ca=True)]
    return [
        tls_record(1, port=8443, src_port=50001, peers=chain, pid=100, process_name="python.exe",
                   exe_path="C:\\Python311\\python.exe", process_attribution="attributed"),                            # 0
        tls_record(4, port=8444, src_port=50002, tls_version="TLS1.2", cipher_suite="ECDHE-RSA-AES256-GCM-SHA384", pid=200,
                   process_name=None, exe_path=None, process_attribution="not_found"),                                    # 1
        tls_record(1, port=9443, src_port=50003, peers=chain, pid=None, process_name=None, exe_path=None,
                   process_attribution="unavailable"),                                                                    # 2 same certificate again
        failed_record(9000, src_port=50004),                                                                              # 3 failed
        failed_record(9001, outcome="incomplete", code="connect_timeout", src_port=50005),                                # 4
        failed_record(9002, outcome="alert", code="tlsv1_alert_protocol_version", src_port=50006),                        # 5
        failed_record(9003, outcome="unknown", code="unrecognised_handshake_details", src_port=50007),                    # 6
        tls_record(5, port=8445, src_port=50008, peers=[peer(5, not_after="2026-03-10T00:00:00Z")]),                       # 7 expiring
        tls_record(6, port=8446, src_port=50009, peers=[peer(6, not_after="2025-12-01T00:00:00Z")]),                       # 8 expired
        tls_record(7, port=8447, src_port=50010, peers=[peer(7, not_before="2027-01-01T00:00:00Z", not_after="2028-01-01T00:00:00Z")]),  # 9 not yet valid
    ]


def seed_tls_run(api, records=None, *, state="completed", summary=None, config=None, run_type="tls"):
    """Create a TLS run in the API's database and bring it to `state`: queued, running, completed, partial or failed.

    'partial' is a normal finish that reports one probe error; 'failed' is a fatal agent failure; 'enumeration_failed' is a
    scan whose OS listener table could not be read. Everything goes through the real ingestion code."""
    records = build_tls_records() if records is None else records
    conn = api.connect()
    try:
        run_id = runs.create_run(conn, run_type, "manual", now=NOW, config=config)
        if state == "queued":
            return run_id
        runs.start_run(conn, run_id, now=at(1))
        if records:
            ingest(conn, run_id, records)
        if state == "running":
            return run_id
        if state == "failed":
            finish(conn, run_id, outcome="failed", fatal_code="boom")
            return run_id
        completed = sum(1 for r in records if r["handshake_outcome"] == "completed")
        if state == "enumeration_failed":
            summary = tls_summary(len(records), completed=completed, enumeration="failed", stop_reason="enumeration_failed",
                                  errors=[tls_error("enumerate", "table_unreadable")])
        else:
            errors = [tls_error("probe", "target_not_local")] if state == "partial" else []
            summary = summary or tls_summary(len(records), completed=completed, errors=errors, listeners_found=len(records) + 2,
                                             policy_skipped=2, targets_planned=len(records), targets_probed=len(records))
        finish(conn, run_id, summary=summary)
        return run_id
    finally:
        conn.close()
