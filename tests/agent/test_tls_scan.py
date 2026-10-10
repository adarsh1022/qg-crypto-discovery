"""TlsScan: enumeration, the plan, counts, cancellation and budgets. Enumeration and process lookup are injected, so no real
service on this machine is ever probed."""
import datetime as dt
import json
import logging
import os

import pytest

from agent.scan_config import ConfigError
from agent.tls_probe import ProbeAborted
from agent.tls_scan import TlsScan, TlsScanConfig
from agent.tls_targets import EnumerationError, Listener, ProcessInfo
from tlsfx import PlainServer, TlsServer, closed_port, make_material

NOW = dt.datetime(2026, 10, 10, 12, 0, 0, tzinfo=dt.timezone.utc)


def scan_of(table, *, config=None, lookup=None, prober=None, should_stop=None, clock=None):
    kwargs = {}
    if prober is not None:
        kwargs["prober"] = prober
    if clock is not None:
        kwargs["clock"] = clock
    return TlsScan(config or TlsScanConfig(), now=lambda: NOW, listeners=lambda: table, should_stop=should_stop,
                   process_lookup=lookup or (lambda pid: ProcessInfo("svc.exe", "C:\\svc\\svc.exe")), **kwargs)


def run(scan):
    records = list(scan.records())
    return records, scan.summary


# ------------------------------------------------------------------ configuration
def test_defaults_are_bounded():
    cfg = TlsScanConfig()
    assert (cfg.max_targets, cfg.connect_timeout_seconds, cfg.handshake_timeout_seconds, cfg.time_budget_seconds, cfg.ports) == (128, 2.0, 3.0, 60.0, None)


def test_from_dict_accepts_the_documented_keys():
    cfg = TlsScanConfig.from_dict({"max_targets": 5, "connect_timeout_seconds": 1, "handshake_timeout_seconds": 2.5,
                                   "time_budget_seconds": 30, "ports": [443, 8443, 443]})
    assert cfg.max_targets == 5 and cfg.ports == (443, 8443) and cfg.connect_timeout_seconds == 1.0
    assert TlsScanConfig.from_dict({}) == TlsScanConfig()


@pytest.mark.parametrize("bad", [
    {"max_targets": 0}, {"max_targets": 1025}, {"max_targets": True}, {"max_targets": 2.5}, {"max_targets": "5"},
    {"connect_timeout_seconds": 0}, {"connect_timeout_seconds": -1}, {"connect_timeout_seconds": 31}, {"connect_timeout_seconds": float("nan")},
    {"handshake_timeout_seconds": "x"}, {"handshake_timeout_seconds": True}, {"time_budget_seconds": 0}, {"time_budget_seconds": 3601},
    {"ports": []}, {"ports": [0]}, {"ports": [65536]}, {"ports": ["443"]}, {"ports": [True]}, {"ports": "443"}, {"ports": list(range(1, 258))},
    {"hosts": ["example.com"]}, {"targets": ["8.8.8.8"]}, {"roots": ["C:\\"]},
])
def test_invalid_configurations_are_refused(bad):
    with pytest.raises(ConfigError):
        TlsScanConfig.from_dict(bad)


def test_a_non_object_configuration_is_refused():
    with pytest.raises(ConfigError):
        TlsScanConfig.from_dict([1])


# ------------------------------------------------------------------ real servers behind a fake listener table
def test_a_wildcard_listener_is_probed_through_loopback_and_counts_are_exact(tmp_path):
    material = make_material(tmp_path)
    with TlsServer(material) as tls, PlainServer() as plain:
        table = [Listener("0.0.0.0", tls.port, os.getpid()), Listener("127.0.0.1", plain.port, 999)]
        records, summary = run(scan_of(table))
    by_port = {r["dst_port"]: r for r in records}
    assert by_port[tls.port]["dst_ip"] == "127.0.0.1"                    # never the wildcard
    assert by_port[tls.port]["handshake_outcome"] == "completed" and by_port[tls.port]["peer_certificates"][0]["sha256"] == material.leaf_sha256
    assert by_port[plain.port]["handshake_outcome"] in ("failed", "incomplete") and by_port[plain.port]["peer_certificates"] == []
    assert by_port[tls.port]["pid"] == os.getpid() and by_port[tls.port]["process_attribution"] == "attributed"
    assert (summary["enumeration"], summary["stop_reason"], summary["complete"]) == ("ok", "completed", True)
    assert (summary["listeners_found"], summary["targets_planned"], summary["targets_probed"], summary["records"]) == (2, 2, 2, 2)
    assert summary["handshakes_completed"] == 1 and sum(summary["records_by_outcome"].values()) == 2
    assert summary["errors"] == [] and summary["errors_total"] == 0


def test_a_port_list_narrows_the_table_and_other_ports_are_never_contacted(tmp_path):
    probed = []

    def spy(target, timeouts, *, now, attribution):
        probed.append(target.port)
        return {"handshake_outcome": "failed", "marker": target.port}

    table = [Listener("127.0.0.1", p, 1) for p in (443, 8443, 9000)]
    records, summary = run(scan_of(table, config=TlsScanConfig(ports=(8443, 55555)), prober=spy))
    assert probed == [8443]                                              # 55555 is not in the table: not probed
    assert summary["port_filtered"] == 2 and summary["targets_planned"] == 1 and summary["listeners_found"] == 3


def test_policy_refused_listeners_are_counted_and_never_contacted():
    probed = []

    def spy(target, timeouts, *, now, attribution):
        probed.append(target.ip)
        return {"handshake_outcome": "failed"}

    table = [Listener("169.254.169.254", 80, 1), Listener("fe80::1%4", 443, 1), Listener("224.0.0.9", 1, 1), Listener("127.0.0.1", 8443, 1)]
    records, summary = run(scan_of(table, prober=spy))
    assert probed == ["127.0.0.1"] and summary["policy_skipped"] == 3


# ------------------------------------------------------------------ enumeration failure is not "no listeners"
def test_a_failed_enumeration_is_distinguishable_from_zero_eligible_listeners():
    def broken():
        raise EnumerationError("table_unreadable")

    failed = TlsScan(TlsScanConfig(), now=lambda: NOW, listeners=broken)
    records, summary = run(failed)
    assert records == [] and summary["enumeration"] == "failed" and summary["stop_reason"] == "enumeration_failed"
    assert summary["errors"] == [{"kind": "enumerate", "code": "table_unreadable"}] and summary["errors_total"] == 1 and not summary["complete"]

    records, summary = run(scan_of([]))
    assert records == [] and summary["enumeration"] == "ok" and summary["stop_reason"] == "completed" and summary["complete"]
    assert summary["listeners_found"] == 0 and summary["errors"] == []

    records, summary = run(scan_of([Listener("169.254.1.1", 80, 1)]))               # listeners exist, none eligible
    assert records == [] and summary["enumeration"] == "ok" and summary["listeners_found"] == 1 and summary["policy_skipped"] == 1


# ------------------------------------------------------------------ errors never become observations
def test_an_aborted_probe_is_an_error_not_a_record_and_the_scan_continues():
    def prober(target, timeouts, *, now, attribution):
        if target.port == 1:
            raise ProbeAborted("target_not_local")
        if target.port == 2:
            raise RuntimeError("secret detail C:\\private\\key.pem")
        return {"handshake_outcome": "failed"}

    table = [Listener("127.0.0.1", p, 1) for p in (1, 2, 3)]
    records, summary = run(scan_of(table, prober=prober))
    assert len(records) == 1 and summary["records"] == 1 and summary["targets_probed"] == 3
    assert summary["errors"] == [{"kind": "probe", "code": "target_not_local"}, {"kind": "probe", "code": "probe_internal_error"}]
    assert "secret" not in json.dumps(summary)


def test_a_failing_process_lookup_means_unavailable_attribution_not_a_failed_scan(tmp_path):
    material = make_material(tmp_path)

    def lookup(pid):
        raise OSError("denied")

    with TlsServer(material) as tls:
        records, summary = run(scan_of([Listener("127.0.0.1", tls.port, 4321)], lookup=lookup))
    assert records[0]["process_attribution"] == "unavailable" or records[0]["process_attribution"] == "not_found"
    assert summary["errors"] == [] and summary["handshakes_completed"] == 1


def test_a_listener_that_vanished_is_an_incomplete_record_not_an_error():
    records, summary = run(scan_of([Listener("127.0.0.1", closed_port(), 1)], config=TlsScanConfig(connect_timeout_seconds=1)))
    assert len(records) == 1 and records[0]["handshake_outcome"] == "incomplete"
    assert summary["handshakes_completed"] == 0 and summary["errors_total"] == 0


# ------------------------------------------------------------------ limits and cancellation
def test_the_target_cap_ends_the_scan_with_target_limit():
    seen = []

    def prober(target, timeouts, *, now, attribution):
        seen.append(target.port)
        return {"handshake_outcome": "failed"}

    table = [Listener("127.0.0.1", 2000 + i, 1) for i in range(6)]
    records, summary = run(scan_of(table, config=TlsScanConfig(max_targets=3), prober=prober))
    assert seen == [2000, 2001, 2002] and summary["stop_reason"] == "target_limit" and summary["targets_truncated"] and not summary["complete"]


def test_cancellation_is_checked_between_targets():
    flag = {"stop": False}
    seen = []

    def prober(target, timeouts, *, now, attribution):
        seen.append(target.port)
        flag["stop"] = True                                              # cancelled while the first probe runs
        return {"handshake_outcome": "failed"}

    table = [Listener("127.0.0.1", 3000 + i, 1) for i in range(5)]
    records, summary = run(scan_of(table, prober=prober, should_stop=lambda: flag["stop"]))
    assert seen == [3000] and len(records) == 1                          # what was found is kept
    assert summary["stop_reason"] == "cancelled" and summary["targets_probed"] == 1


def test_cancellation_before_the_first_target_probes_nothing():
    seen = []
    records, summary = run(scan_of([Listener("127.0.0.1", 4000, 1)], prober=lambda *a, **k: seen.append(1), should_stop=lambda: True))
    assert seen == [] and records == [] and summary["stop_reason"] == "cancelled" and summary["enumeration"] == "ok"


def test_the_time_budget_stops_the_scan():
    ticks = iter(range(0, 1000, 20))                                     # every clock reading is 20 s later
    table = [Listener("127.0.0.1", 5000 + i, 1) for i in range(10)]
    records, summary = run(scan_of(table, config=TlsScanConfig(time_budget_seconds=50), clock=lambda: next(ticks),
                                   prober=lambda target, timeouts, *, now, attribution: {"handshake_outcome": "failed"}))
    assert summary["stop_reason"] == "time_limit" and 0 < len(records) < 10


def test_closing_the_generator_early_is_a_cancellation():
    scan = scan_of([Listener("127.0.0.1", 6000 + i, 1) for i in range(3)], prober=lambda *a, **k: {"handshake_outcome": "failed"})
    gen = scan.records()
    next(gen)
    gen.close()
    assert scan.summary["stop_reason"] == "cancelled"


def test_a_scan_can_be_consumed_only_once():
    scan = scan_of([])
    list(scan.records())
    with pytest.raises(RuntimeError):
        list(scan.records())


# ------------------------------------------------------------------ nothing sensitive
def test_the_summary_and_logs_hold_no_certificate_content(tmp_path, caplog):
    material = make_material(tmp_path, chain=True)
    with caplog.at_level(logging.DEBUG):
        with TlsServer(material) as tls:
            records, summary = run(scan_of([Listener("127.0.0.1", tls.port, 1)]))
    text = json.dumps(summary)
    assert material.leaf_sha256 not in text and "BEGIN" not in text
    for der in material.ders:
        assert der.hex() not in text.lower()
    assert material.key_pem.decode().splitlines()[1] not in text and caplog.text == ""


def test_summary_is_json_serialisable_and_has_the_documented_keys(tmp_path):
    records, summary = run(scan_of([]))
    assert set(summary) == {"stop_reason", "complete", "enumeration", "listeners_found", "port_filtered", "policy_skipped", "targets_planned",
                            "targets_probed", "records", "handshakes_completed", "targets_truncated", "records_by_outcome", "errors",
                            "errors_total", "elapsed_seconds"}
    json.dumps(summary, allow_nan=False)
