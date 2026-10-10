"""The real agent runner executing TLS runs against the real API app (in-process transport) and real local TLS servers.

Enumeration is replaced by a fake OS listener table that points ONLY at the test's own servers, so no real service on this
machine is ever probed; the handshakes themselves are real."""
import logging
import os
import threading
import time

import pytest

from agent.runner import poll_once, run_claimed
from agent.tls_scan import TlsScan
from agent.tls_targets import Listener
from agentfx import make_client, options
from apifx import make_api
from backend import db, runs
from tlsfx import PlainServer, SilentServer, TlsServer, closed_port, make_material


def factory_for(table, **scan_kwargs):
    """A tls_scan_factory whose 'OS listener table' is `table`."""
    def make(config, should_stop=None, **_):
        return TlsScan(config, should_stop=should_stop, listeners=lambda: table, **scan_kwargs)
    return make


def run_of(api, **config):
    return api.create("tls", config=config)["run_id"]


def rows(api, sql, *args):
    with api.connect() as conn:
        return [dict(r) for r in conn.execute(sql, args)]


# ------------------------------------------------------------------ a real scan, end to end through the protocol
def test_a_tls_run_is_scanned_uploaded_and_finalized_with_the_servers_real_certificate(tmp_path):
    material = make_material(tmp_path)
    api = make_api(tmp_path)
    run_id = run_of(api)
    with TlsServer(material) as tls, PlainServer() as plain:
        table = [Listener("0.0.0.0", tls.port, os.getpid()), Listener("127.0.0.1", plain.port, os.getpid())]
        client, wire = make_client(api)
        report = poll_once(client, options(), tls_scan_factory=factory_for(table))
    assert (report.outcome, report.final_status, report.records_sent, report.accepted) == ("finished", "completed", 2, 2)
    run = api.get(run_id)
    assert (run["status"], run["record_count"], run["finding_count"], run["error_count"]) == ("completed", 2, 1, 0)
    assert run["agent_summary"]["enumeration"] == "ok" and run["agent_summary"]["handshakes_completed"] == 1

    stored = {r["dst_port"]: r for r in rows(api, "SELECT * FROM tls_observations WHERE run_id = ?", run_id)}
    good, other = stored[tls.port], stored[plain.port]
    assert (good["handshake_outcome"], good["direction"], good["dst_ip"], good["cert_visibility"]) == ("completed", "unknown", "127.0.0.1", "visible")
    assert good["tls_version"] in ("TLS1.2", "TLS1.3") and good["cipher_suite"]
    assert (good["pid"], good["process_attribution"]) == (os.getpid(), "attributed") and good["process_name"].lower().startswith("python")
    assert (good["local_ip"], good["remote_ip"], good["packet_count"], good["event_count"]) == (None, None, 0, 1)
    peers = rows(api, "SELECT sha256 FROM tls_peer_certificates WHERE tls_observation_id = ? ORDER BY position", good["id"])
    assert [p["sha256"] for p in peers] == [material.leaf_sha256]                  # the certificate the server really presented

    assert other["handshake_outcome"] in ("failed", "incomplete") and other["tls_version"] is None and other["cipher_suite"] is None
    assert other["cert_visibility"] == "not_observed"
    assert rows(api, "SELECT COUNT(*) AS n FROM tls_peer_certificates WHERE tls_observation_id = ?", other["id"])[0]["n"] == 0
    assert [c["sha256"] for c in rows(api, "SELECT sha256 FROM certificates")] == [material.leaf_sha256]    # nothing fabricated
    assert tls.received == b""                                                     # the probe sent no application data


def test_nothing_but_facts_travels_to_the_backend(tmp_path):
    material = make_material(tmp_path, chain=True)
    api = make_api(tmp_path)
    run_of(api)
    with TlsServer(material) as tls:
        client, wire = make_client(api)
        poll_once(client, options(), tls_scan_factory=factory_for([Listener("127.0.0.1", tls.port, 1)]))
    sent = b"".join(c[2] or b"" for c in wire.paths("/observations")).lower()
    for der in material.ders:
        assert der.hex().encode() not in sent
    assert b"begin" not in sent and b"private" not in sent and material.key_pem.splitlines()[1].lower() not in sent
    assert [r["position"] for r in rows(api, "SELECT position FROM tls_peer_certificates ORDER BY position")] == [0, 1, 2]


def test_a_machine_with_no_tls_services_gives_a_completed_run_with_zero_records(tmp_path):
    api = make_api(tmp_path)
    run_id = run_of(api)
    client, _ = make_client(api)
    report = poll_once(client, options(), tls_scan_factory=factory_for([]))
    run = api.get(run_id)
    assert report.outcome == "finished" and (run["status"], run["record_count"], run["finding_count"]) == ("completed", 0, 0)
    assert run["agent_summary"]["enumeration"] == "ok" and run["agent_summary"]["listeners_found"] == 0


def test_a_failed_enumeration_fails_the_run_honestly(tmp_path):
    from agent.tls_targets import EnumerationError

    def broken():
        raise EnumerationError("table_unreadable")

    api = make_api(tmp_path)
    run_id = run_of(api)
    client, _ = make_client(api)
    poll_once(client, options(), tls_scan_factory=lambda config, should_stop=None, **_: TlsScan(config, should_stop=should_stop, listeners=broken))
    run = api.get(run_id)
    assert run["status"] == "failed" and run["error_count"] == 1 and run["error_summary"].startswith("no_usable_data")


def test_the_port_list_in_the_run_configuration_only_narrows_what_is_probed(tmp_path):
    material = make_material(tmp_path)
    api = make_api(tmp_path)
    with TlsServer(material) as wanted, TlsServer(material) as other:
        run_id = run_of(api, ports=[wanted.port, 1])                               # port 1 is not listening: never probed
        table = [Listener("127.0.0.1", wanted.port, 1), Listener("127.0.0.1", other.port, 1)]
        client, _ = make_client(api)
        poll_once(client, options(), tls_scan_factory=factory_for(table))
        assert other.connections == 0 and wanted.connections == 1
    run = api.get(run_id)
    assert run["record_count"] == 1 and run["agent_summary"]["port_filtered"] == 1


# ------------------------------------------------------------------ the agent's own configuration check (defence in depth)
@pytest.mark.parametrize("config", [{"hosts": ["example.com"]}, {"targets": ["8.8.8.8:443"]}, {"max_targets": 5, "roots": ["C:\\"]}])
def test_the_agent_still_refuses_a_configuration_that_bypassed_backend_validation(tmp_path, config):
    """The backend refuses unknown keys at creation, so such a run cannot be created through the API. If one existed anyway
    (written straight into the database), the agent refuses it too and fails the run without probing anything."""
    api = make_api(tmp_path)
    with api.connect() as conn:
        run_id = runs.create_run(conn, "tls", "manual", now=api.clock(), config=config)          # domain call: no API validation
    seen = []
    client, wire = make_client(api)
    report = poll_once(client, options(), tls_scan_factory=lambda *a, **k: seen.append(1))
    run = api.get(run_id)
    assert (report.outcome, report.detail) == ("failed", "invalid_config") and run["status"] == "failed" and seen == []
    assert wire.uploads() == []


# ------------------------------------------------------------------ the shared lifecycle behaviours, for a TLS run
def test_cancellation_stops_the_scan_between_targets_and_ends_partial(tmp_path):
    api = make_api(tmp_path)
    run_id = run_of(api)
    with PlainServer() as a, PlainServer() as b, PlainServer() as c, PlainServer() as d:
        table = [Listener("127.0.0.1", s.port, 1) for s in (a, b, c, d)]

        def cancel_after_first_upload(wire, method, path, body, response):
            if path.endswith("/observations") and len(wire.paths("/observations")) == 1:
                assert api.cancel(run_id).status_code == 200

        client, wire = make_client(api, after=cancel_after_first_upload)
        report = poll_once(client, options(batch_size=1), tls_scan_factory=factory_for(table))
    run = api.get(run_id)
    assert report.cancelled and run["status"] == "partial" and "stopped_cancelled" in run["error_summary"]
    assert 1 <= run["record_count"] < 4 and run["agent_summary"]["stop_reason"] == "cancelled"


def test_heartbeats_keep_flowing_while_a_probe_is_slow(tmp_path):
    api = make_api(tmp_path, heartbeat_interval_s=0.05)
    run_id = run_of(api, handshake_timeout_seconds=1, connect_timeout_seconds=1)
    with SilentServer() as silent:
        client, wire = make_client(api)
        report = poll_once(client, options(), tls_scan_factory=factory_for([Listener("127.0.0.1", silent.port, 1)]))
    assert report.outcome == "finished" and len(wire.paths("/heartbeat")) >= 3
    run = api.get(run_id)
    assert run["status"] == "completed" and run["record_count"] == 1 and run["finding_count"] == 0


def test_a_lost_response_is_replayed_without_duplicating_observations(tmp_path):
    material = make_material(tmp_path)
    api = make_api(tmp_path)
    run_id = run_of(api)
    failed = []

    def drop_once(wire, method, path, body, response):
        if path.endswith("/observations") and not failed:
            failed.append(1)
            raise ConnectionResetError("response lost")

    with TlsServer(material) as tls, PlainServer() as plain:
        client, wire = make_client(api, after=drop_once)
        report = poll_once(client, options(), tls_scan_factory=factory_for([Listener("127.0.0.1", tls.port, 1), Listener("127.0.0.1", plain.port, 1)]))
    assert report.outcome == "finished" and report.duplicates == 2
    run = api.get(run_id)
    assert (run["status"], run["record_count"], run["finding_count"]) == ("completed", 2, 1)
    assert len(rows(api, "SELECT id FROM tls_observations")) == 2 and len(rows(api, "SELECT sha256 FROM certificates")) == 1


def test_a_lost_lease_stops_the_agent_without_hammering_the_backend(tmp_path):
    api = make_api(tmp_path)
    run_id = run_of(api)

    def lease_runs_out(wire, method, path, body):
        if path.endswith("/observations") and not wire.paths("/observations"):
            api.clock.advance(10_000)

    with PlainServer() as a, PlainServer() as b:
        client, wire = make_client(api, before=lease_runs_out)
        report = poll_once(client, options(batch_size=1), tls_scan_factory=factory_for([Listener("127.0.0.1", a.port, 1), Listener("127.0.0.1", b.port, 1)]))
    assert report.outcome == "lost" and len(wire.paths("/observations")) == 1 and wire.paths("/finish") == []
    assert api.get(run_id)["status"] in ("partial", "failed")


def test_shutdown_fails_the_run_as_agent_stopped(tmp_path):
    api = make_api(tmp_path)
    run_id = run_of(api)
    shutdown = threading.Event()

    def stop_after_first_upload(wire, method, path, body, response):
        if path.endswith("/observations"):
            shutdown.set()

    with PlainServer() as a, PlainServer() as b, PlainServer() as c:
        client, _ = make_client(api, after=stop_after_first_upload)
        report = poll_once(client, options(batch_size=1), shutdown, tls_scan_factory=factory_for([Listener("127.0.0.1", s.port, 1) for s in (a, b, c)]))
    assert (report.outcome, report.detail) == ("failed", "agent_stopped") and api.get(run_id)["status"] == "failed"


def test_a_scanner_bug_fails_the_run_and_leaks_nothing(tmp_path, caplog):
    api = make_api(tmp_path)
    run_id = run_of(api)

    class Broken:
        def __init__(self, config, should_stop=None, **_):
            pass

        def records(self):
            raise RuntimeError(f"secret detail {tmp_path}")
            yield

        summary = {}

    client, _ = make_client(api)
    with caplog.at_level(logging.DEBUG):
        report = poll_once(client, options(), tls_scan_factory=Broken)
    assert (report.outcome, report.detail) == ("failed", "agent_error") and api.get(run_id)["status"] == "failed"
    assert "secret" not in caplog.text and str(tmp_path) not in caplog.text


def test_logs_hold_no_certificate_content_addresses_or_paths(tmp_path, caplog):
    material = make_material(tmp_path)
    api = make_api(tmp_path)
    run_of(api)
    with caplog.at_level(logging.DEBUG):
        with TlsServer(material) as tls:
            client, _ = make_client(api)
            poll_once(client, options(), tls_scan_factory=factory_for([Listener("127.0.0.1", tls.port, os.getpid())]))
    assert material.leaf_sha256 not in caplog.text and "BEGIN" not in caplog.text and "python" not in caplog.text.lower().replace("pythonscripts", "")
    assert "claimed run" in caplog.text


def test_the_filesystem_path_still_works_next_to_tls(tmp_path):
    from test_api_e2e import build_tree
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    fs_run = api.create(config={"roots": [str(tree)]})["run_id"]
    tls_run = run_of(api)
    client, _ = make_client(api)
    first = poll_once(client, options())                                            # filesystem run is older: taken first, real Scan
    second = poll_once(client, options(), tls_scan_factory=factory_for([]))
    assert (first.run_id, second.run_id) == (fs_run, tls_run)
    assert (api.get(fs_run)["status"], api.get(fs_run)["record_count"], api.get(fs_run)["finding_count"]) == ("completed", 8, 6)
    assert api.get(tls_run)["status"] == "completed"
    _ = (closed_port, db, time, run_claimed)


def test_a_run_lost_to_another_agent_is_skipped_across_types(tmp_path):
    api = make_api(tmp_path)
    tls_run = run_of(api)
    fs_run = api.create(config={"roots": [str(tmp_path)]})["run_id"]
    rival = api.agent(agent_id="rival")

    def steal_after_listing(wire, method, path, body, response):
        if method == "GET" and not wire.paths("/claim"):
            assert rival.claim(tls_run).status_code == 200                       # the older TLS run is taken by someone else

    client, _ = make_client(api, after=steal_after_listing)
    report = poll_once(client, options(), tls_scan_factory=factory_for([]))
    assert report.run_id == fs_run and report.outcome == "finished"
    assert api.get(tls_run)["status"] == "running" and api.get(fs_run)["status"] == "completed"


def test_a_run_type_the_agent_cannot_execute_is_failed_not_scanned():
    calls = []

    class Client:
        def finish(self, run_id, token, **kwargs):
            calls.append(kwargs)
            return {"run": {"status": "failed"}}

        def heartbeat(self, *a):
            return {"status": "running", "cancel_requested": False}

    claim = {"run": {"run_id": "a" * 32, "type": "packet_capture", "config": {}}, "lease_token": "b" * 32, "lease": {}, "limits": {}}
    report = run_claimed(Client(), claim, options(), threading.Event(), scan_factory=lambda *a, **k: pytest.fail("scanned"),
                         tls_scan_factory=lambda *a, **k: pytest.fail("scanned"))
    assert (report.outcome, report.detail) == ("failed", "unsupported_run_type")
    assert calls == [{"outcome": "failed", "summary": None, "fatal_code": "unsupported_run_type"}]
