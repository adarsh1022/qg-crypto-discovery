"""Row builders for schema tests: each returns a complete valid row that tests then break one field at a time."""
import itertools

T_MS = "2026-01-01T00:00:00.000Z"
LEASE_HASH = "c" * 64
T_S = "2026-01-01T00:00:00Z"
SHA_A = "a" * 64
SHA_B = "b" * 64

_counter = itertools.count(1)


def insert(conn, table, row):
    names = ", ".join(row)
    marks = ", ".join("?" for _ in row)
    return conn.execute(f"INSERT INTO {table} ({names}) VALUES ({marks})", tuple(row.values()))


def run_row(**overrides):
    n = next(_counter)
    row = dict(run_id=f"run-{n:08d}", run_number=n, type="filesystem", run_trigger="manual", status="queued",
               queued_at=T_MS)
    row.update(overrides)
    if row["status"] == "running" and "lease_hash" not in overrides:
        row["lease_hash"] = LEASE_HASH                    # a running run always has an owner (migration 0003)
    return row


def make_run(conn, **overrides):
    row = run_row(**overrides)
    insert(conn, "runs", row)
    return row["run_id"]


def cert_row(run_id, sha256=SHA_A, **overrides):
    row = dict(sha256=sha256, serial_hex="01", subject="CN=a", issuer="CN=ca", key_algorithm="RSA", key_size=2048,
               signature_algorithm="sha256WithRSAEncryption", not_before=T_S, not_after="2027-01-01T00:00:00Z",
               first_seen_run=run_id, first_seen_at=T_S, last_seen_run=run_id, last_seen_at=T_S)
    row.update(overrides)
    return row


def make_cert(conn, run_id, sha256=SHA_A, **overrides):
    insert(conn, "certificates", cert_row(run_id, sha256, **overrides))
    return sha256


def fs_row(run_id, seq=0, **overrides):
    row = dict(run_id=run_id, seq=seq, entry_ordinal=0, path=r"C:\certs\a.pem", filename="a.pem",
               scan_root=r"C:\certs", format="pem", discovered_at=T_S, sha256=SHA_A, chain_index=0, chain_total=1,
               chain_role="leaf", parse_status="ok", evidence_confidence="high", validity_status="valid",
               days_to_expiry=100, not_yet_valid=0)
    row.update(overrides)
    return row


def fs_failure_row(run_id, seq=0, **overrides):
    """A file that produced no certificate."""
    row = dict(run_id=run_id, seq=seq, entry_ordinal=0, path=r"C:\certs\b.pem", filename="b.pem",
               scan_root=r"C:\certs", format="unknown", discovered_at=T_S, parse_status="access_denied",
               evidence_confidence="low")
    row.update(overrides)
    return row


def tls_row(run_id, seq=0, **overrides):
    row = dict(run_id=run_id, seq=seq, observed_at=T_S, direction="outbound", src_ip="10.0.0.2", src_port=50000,
               dst_ip="93.184.216.34", dst_port=443, handshake_outcome="completed", cert_visibility="visible",
               evidence_confidence="high")
    row.update(overrides)
    return row


def make_node(conn, kind, key):
    cur = insert(conn, "nodes", dict(kind=kind, node_key=key, label=key, first_seen_at=T_S, last_seen_at=T_S))
    return cur.lastrowid


def edge_row(src, dst, kind, **overrides):
    row = dict(src_node=src, dst_node=dst, kind=kind, observation_count=1, run_count=1,
               first_seen_at=T_S, last_seen_at=T_S)
    row.update(overrides)
    return row
