"""TLS discovery over real sockets and real processes: a real backend, the real agent, real local TLS servers.

Two tests:
  * the real runner and scanner over real HTTP to a real uvicorn server (the OS listener table is faked, pointing only at the
    test's own servers);
  * `python -m backend` and `python -m agent --once` as separate processes with REAL listener enumeration and REAL process
    attribution. The run's port list narrows the OS table to the test's own servers, so no other service is probed."""
import base64
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

import pemgen
from agent.client import BackendClient
from agent.runner import poll_once
from agent.tls_scan import TlsScan
from agent.tls_targets import Listener
from agentfx import options
from backend import db
from test_server_e2e import REPO, ThreadServer, free_port, wait_for
from tlsfx import PlainServer, SilentServer, TlsServer, make_material


def stored(db_path, sql, *args):
    conn = db.connect(db_path, read_only=True)
    try:
        return [dict(r) for r in conn.execute(sql, args)]
    finally:
        conn.close()


def database_bytes(db_path: Path) -> bytes:
    return b"".join(p.read_bytes() for p in (db_path, Path(f"{db_path}-wal")) if p.exists())


def assert_no_secret_material(db_path, material):
    blob = database_bytes(db_path)
    for der in material.ders:
        assert der not in blob and base64.b64encode(der) not in blob and der.hex().encode() not in blob.lower()
    assert b"-----BEGIN" not in blob
    assert not pemgen.leaked(blob.decode("latin-1"), pemgen.canary_set(material.key_pem))


def only_a_client_hello(received: bytes) -> bool:
    """True if `received` is nothing, or only ONE TLS handshake record (the ClientHello): no application data, no second record.
    (A plain-text listener may close the connection before it reads the hello, so empty is possible too.)"""
    return received == b"" or len(received) >= 5 and received[0] == 0x16 and received[1] == 0x03 and len(received) == 5 + int.from_bytes(received[3:5], "big")


def check_results(base, run_id, db_path, material, tls_port, plain_port):
    run = httpx.get(f"{base}/api/runs/{run_id}").json()["run"]
    assert run["status"] == "completed" and run["record_count"] == 2 and run["finding_count"] == 1 and run["error_count"] == 0, run
    assert run["agent_summary"]["enumeration"] == "ok" and run["agent_summary"]["handshakes_completed"] == 1
    by_port = {r["dst_port"]: r for r in stored(db_path, "SELECT * FROM tls_observations WHERE run_id = ?", run_id)}
    assert set(by_port) == {tls_port, plain_port}
    good, other = by_port[tls_port], by_port[plain_port]
    assert (good["handshake_outcome"], good["direction"], good["transport"]) == ("completed", "unknown", "tcp")
    assert good["tls_version"] in ("TLS1.2", "TLS1.3") and good["cipher_suite"] and good["cert_visibility"] == "visible"
    assert (good["dst_ip"], good["src_ip"]) == ("127.0.0.1", "127.0.0.1") and good["src_port"] not in (0, tls_port)
    assert (good["local_ip"], good["remote_ip"], good["packet_count"], good["event_count"]) == (None, None, 0, 1)
    peers = stored(db_path, "SELECT sha256 FROM tls_peer_certificates WHERE tls_observation_id = ? ORDER BY position", good["id"])
    assert [p["sha256"] for p in peers] == [material.leaf_sha256]                                  # the real server certificate
    cert = stored(db_path, "SELECT * FROM certificates WHERE sha256 = ?", material.leaf_sha256)
    assert len(cert) == 1 and cert[0]["subject"] == "CN=probe-test.local"
    # a non-TLS listener never becomes a TLS service or a certificate
    assert other["handshake_outcome"] in ("failed", "incomplete") and other["tls_version"] is None and other["cipher_suite"] is None
    assert other["cert_visibility"] == "not_observed"
    assert stored(db_path, "SELECT COUNT(*) AS n FROM tls_peer_certificates WHERE tls_observation_id = ?", other["id"])[0]["n"] == 0
    assert stored(db_path, "SELECT COUNT(*) AS n FROM certificates")[0]["n"] == 1
    check_report_api(base, run_id, material, tls_port, plain_port)
    return good


def check_report_api(base, run_id, material, tls_port, plain_port):
    """The TLS report endpoints, read over real HTTP after a real probe run: the same facts, nothing more."""
    summary = httpx.get(f"{base}/api/runs/{run_id}/tls/summary")
    assert summary.status_code == 200 and summary.headers["cache-control"] == "no-store"
    totals = summary.json()["totals"]
    assert (totals["probe_attempts"], totals["handshakes_completed"], totals["not_completed"]) == (2, 1, 1)
    assert (totals["certificates_presented"], totals["leaf_certificates"], totals["endpoints"]) == (1, 1, 2)
    assert summary.json()["scan"]["enumeration"] == "ok" and summary.json()["issues"]["errors"]["total"] == 0
    page = httpx.get(f"{base}/api/runs/{run_id}/tls/observations").json()
    by_port = {item["dst_port"]: item for item in page["items"]}
    good, other = by_port[tls_port], by_port[plain_port]
    assert good["handshake_outcome"] == "completed" and good["direction"] == "unknown" and (good["event_count"], good["packet_count"]) == (1, 0)
    assert [p["sha256"] for p in good["peer_certificates"]] == [material.leaf_sha256]          # the certificate the server really presented
    assert good["peer_certificates"][0]["subject"] == "CN=probe-test.local"
    assert other["handshake_outcome"] in ("failed", "incomplete") and other["peer_certificates"] == []   # a non-TLS listener is no certificate
    assert other["tls_version"] is None and other["cipher_suite"] is None
    lookup = httpx.get(f"{base}/api/runs/{run_id}/tls/observations", params={"fingerprint": material.leaf_sha256}).json()
    assert [item["dst_port"] for item in lookup["items"]] == [tls_port]
    everything = summary.text + httpx.get(f"{base}/api/runs/{run_id}/tls/observations").text + httpx.get(f"{base}/api/runs/{run_id}/tls/issues").text
    for der in material.ders:
        assert der.hex() not in everything.lower() and base64.b64encode(der).decode() not in everything
    assert "BEGIN" not in everything and not pemgen.leaked(everything, pemgen.canary_set(material.key_pem))
    assert httpx.get(f"{base}/api/runs/{run_id}/fs/summary").status_code == 409                      # the filesystem report still refuses a TLS run


def test_real_server_real_agent_real_handshakes(tmp_path):
    material = make_material(tmp_path)
    db_path = tmp_path / "tls-e2e.db"
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    with TlsServer(material) as tls, PlainServer() as plain, ThreadServer(db_path, port):
        wait_for(f"{base}/api/meta")
        created = httpx.post(f"{base}/api/runs", json={"type": "tls", "config": {"ports": [tls.port, plain.port]}})
        assert created.status_code == 201 and created.json()["run"]["type"] == "tls"
        run_id = created.json()["run"]["run_id"]
        table = [Listener("0.0.0.0", tls.port, os.getpid()), Listener("127.0.0.1", plain.port, os.getpid()),
                 Listener("127.0.0.1", 1, os.getpid())]            # port 1 is outside the run's port list: never probed
        factory = lambda config, should_stop=None, **_: TlsScan(config, should_stop=should_stop, listeners=lambda: table)  # noqa: E731
        report = poll_once(BackendClient(base), options(), tls_scan_factory=factory)
        assert (report.outcome, report.final_status, report.batches) == ("finished", "completed", 1)
        good = check_results(base, run_id, db_path, material, tls.port, plain.port)
        assert (good["pid"], good["process_attribution"]) == (os.getpid(), "attributed")
        # no application data to either listener: the TLS server saw nothing after the handshake, and the plain-text listener
        # received at most one TLS ClientHello (the handshake attempt itself) and nothing else
        assert tls.received == b"" and only_a_client_hello(plain.received)
    assert_no_secret_material(db_path, material)


def test_cancelling_over_real_http_ends_the_run_partial(tmp_path):
    db_path = tmp_path / "tls-cancel.db"
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    with SilentServer() as a, SilentServer() as b, SilentServer() as c, SilentServer() as d, SilentServer() as e, SilentServer() as f, ThreadServer(db_path, port):
        wait_for(f"{base}/api/meta")
        run_id = httpx.post(f"{base}/api/runs", json={"type": "tls", "config": {"handshake_timeout_seconds": 0.3, "connect_timeout_seconds": 1}}).json()["run"]["run_id"]
        table = [Listener("127.0.0.1", s.port, 1) for s in (a, b, c, d, e, f)]
        client = BackendClient(base)
        original = client.upload
        uploads = []

        def cancel_after_first(run, token, items):
            answer = original(run, token, items)
            if not uploads:
                assert httpx.post(f"{base}/api/runs/{run}/cancel").status_code == 200
            uploads.append(1)
            return answer

        client.upload = cancel_after_first
        factory = lambda config, should_stop=None, **_: TlsScan(config, should_stop=should_stop, listeners=lambda: table)  # noqa: E731
        report = poll_once(client, options(batch_size=1), tls_scan_factory=factory)
        assert report.cancelled and report.final_status == "partial"
        run = httpx.get(f"{base}/api/runs/{run_id}").json()["run"]
        assert run["status"] == "partial" and "stopped_cancelled" in run["error_summary"] and 1 <= run["record_count"] < 6


def test_backend_and_agent_as_separate_processes_with_real_enumeration(tmp_path):
    material = make_material(tmp_path)
    db_path = tmp_path / "data" / "agent.db"
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8"}
    out = tmp_path / "backend.out"
    with TlsServer(material) as tls, PlainServer() as plain, open(out, "wb") as sink:
        server = subprocess.Popen([sys.executable, "-m", "backend", "--db", str(db_path), "--port", str(port)], cwd=REPO, env=env,
                                  stdout=sink, stderr=subprocess.STDOUT)
        try:
            wait_for(f"{base}/api/meta")
            # the port list narrows the REAL OS listener table to the test's own two servers: nothing else is probed
            run_id = httpx.post(f"{base}/api/runs", json={"type": "tls", "config": {"ports": [tls.port, plain.port]}}).json()["run"]["run_id"]
            agent = subprocess.run([sys.executable, "-m", "agent", "--server", base, "--once"], cwd=REPO, env=env, capture_output=True,
                                   text=True, timeout=120)
            assert agent.returncode == 0, (agent.stdout, agent.stderr)
            assert f"run {run_id}: finished" in agent.stdout and "2 records" in agent.stdout
            good = check_results(base, run_id, db_path, material, tls.port, plain.port)
            # real process attribution: the listener belongs to THIS test process, resolved by the agent from the OS
            assert (good["pid"], good["process_attribution"]) == (os.getpid(), "attributed")
            assert good["process_name"].lower().startswith("python") and good["exe_path"].lower().endswith(".exe")
            output = agent.stdout + agent.stderr
            assert material.leaf_sha256 not in output and "BEGIN" not in output and good["exe_path"] not in output
            assert tls.received == b"" and only_a_client_hello(plain.received)
        finally:
            server.terminate()
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill()
    text = out.read_text(encoding="utf-8", errors="replace")
    assert "GET /api" not in text and "POST /api" not in text and material.leaf_sha256 not in text
    assert_no_secret_material(db_path, material)


def test_an_unknown_configuration_key_is_refused_over_real_http_and_nothing_is_probed(tmp_path):
    db_path = tmp_path / "tls-bad.db"
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    with ThreadServer(db_path, port):
        wait_for(f"{base}/api/meta")
        refused = httpx.post(f"{base}/api/runs", json={"type": "tls", "config": {"hosts": ["8.8.8.8"]}})
        assert refused.status_code == 422 and refused.json()["error"]["code"] == "invalid_config"
        assert refused.json()["error"]["details"]["problem"] == "unknown_key"
        assert httpx.get(f"{base}/api/runs").json()["runs"] == []                    # no run exists, so no agent can claim it
        seen = []
        assert poll_once(BackendClient(base), options(), tls_scan_factory=lambda *a, **k: seen.append(1)) is None and seen == []
    assert stored(db_path, "SELECT COUNT(*) AS n FROM tls_observations")[0]["n"] == 0
    assert stored(db_path, "SELECT COUNT(*) AS n FROM runs")[0]["n"] == 0
    _ = pytest
