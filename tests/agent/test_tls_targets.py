"""The local-target policy: only literal addresses of listeners on this machine, wildcards replaced by loopback, no fallbacks."""
import os
import sys

import pytest

from agent import tls_targets as tt
from agent.tls_targets import EnumerationError, Listener, ProcessInfo, TargetRejected, build_plan, destination_for, validate_destination


# ------------------------------------------------------------------ validate_destination
@pytest.mark.parametrize("ip", ["127.0.0.1", "127.0.0.2", "::1", "10.1.2.3", "192.168.1.6", "172.16.5.5", "8.8.8.8", "2001:db8::1"])
def test_literal_addresses_pass_the_syntax_policy(ip):
    assert validate_destination(ip)                     # whether an address is LOCAL is proven by the probe's bind, not here


@pytest.mark.parametrize("value,code", [
    ("example.com", "not_an_ip_address"), ("localhost", "not_an_ip_address"), ("", "not_an_ip_address"), (None, "not_an_ip_address"),
    (5, "not_an_ip_address"), ("127.0.0.1:443", "not_an_ip_address"), ("http://127.0.0.1", "not_an_ip_address"),
    ("127.0.0.1 ", "not_an_ip_address"), ("0x7f.0.0.1", "not_an_ip_address"), ("2130706433", "not_an_ip_address"),
    ("fe80::1%12", "scoped_address"), ("::1%1", "scoped_address"),
    ("::ffff:127.0.0.1", "ipv4_mapped_address"), ("::ffff:8.8.8.8", "ipv4_mapped_address"),
    ("0.0.0.0", "unspecified_address"), ("::", "unspecified_address"),
    ("224.0.0.1", "multicast_address"), ("ff02::1", "multicast_address"),
    ("169.254.169.254", "link_local_address"), ("169.254.1.1", "link_local_address"), ("fe80::1", "link_local_address"),
    ("240.0.0.1", "reserved_address"), ("255.255.255.255", "reserved_address"),
])
def test_everything_else_is_refused_with_a_fixed_code(value, code):
    with pytest.raises(TargetRejected) as refused:
        validate_destination(value)
    assert refused.value.code == code
    if isinstance(value, str) and value:
        assert value not in str(refused.value)           # the offending text is never echoed


# ------------------------------------------------------------------ wildcards
def test_wildcards_become_explicit_loopback_and_are_never_destinations():
    assert destination_for(Listener("0.0.0.0", 443, 1)) == "127.0.0.1"
    assert destination_for(Listener("::", 443, 1)) == "::1"
    assert destination_for(Listener("::%0", 443, 1)) == "::1"
    plan = build_plan([Listener("0.0.0.0", 443, 1), Listener("::", 443, 1)], max_targets=10)
    assert {t.ip for t in plan.targets} == {"127.0.0.1", "::1"}
    assert "0.0.0.0" not in {t.ip for t in plan.targets} and "::" not in {t.ip for t in plan.targets}


def test_a_specific_bound_address_is_probed_at_that_address_and_nowhere_else():
    plan = build_plan([Listener("192.168.1.6", 8443, 7)], max_targets=10)
    assert [(t.ip, t.port) for t in plan.targets] == [("192.168.1.6", 8443)]


# ------------------------------------------------------------------ plan
def test_listeners_whose_destination_the_policy_refuses_are_skipped_and_counted_never_replaced():
    table = [Listener("169.254.10.1", 443, 1), Listener("fe80::1%5", 443, 1), Listener("224.0.0.1", 443, 1),
             Listener("not-an-ip", 443, 1), Listener("127.0.0.1", 8443, 2)]
    plan = build_plan(table, max_targets=10)
    assert [(t.ip, t.port) for t in plan.targets] == [("127.0.0.1", 8443)]
    assert (plan.listeners_found, plan.policy_skipped, plan.port_filtered) == (5, 4, 0)


def test_invalid_ports_are_skipped():
    plan = build_plan([Listener("127.0.0.1", 0, 1), Listener("127.0.0.1", 70000, 1), Listener("127.0.0.1", 443, 1)], max_targets=10)
    assert [t.port for t in plan.targets] == [443] and plan.policy_skipped == 2


def test_a_port_list_only_narrows_the_os_table_and_never_adds_a_target():
    table = [Listener("127.0.0.1", 443, 1), Listener("127.0.0.1", 8443, 2), Listener("0.0.0.0", 9000, 3)]
    plan = build_plan(table, max_targets=10, ports=frozenset({443, 9000, 12345}))     # 12345 is not listening
    assert sorted(t.port for t in plan.targets) == [443, 9000]
    assert plan.port_filtered == 1 and plan.listeners_found == 3
    assert build_plan(table, max_targets=10, ports=frozenset({12345})).targets == ()


def test_targets_are_deduplicated_and_ordered_deterministically():
    table = [Listener("0.0.0.0", 9000, 1), Listener("127.0.0.1", 9000, 1), Listener("127.0.0.1", 80, 2), Listener("0.0.0.0", 80, 2)]
    plan = build_plan(table, max_targets=10)
    assert [(t.port, t.ip) for t in plan.targets] == [(80, "127.0.0.1"), (9000, "127.0.0.1")]
    assert plan == build_plan(list(reversed(table)), max_targets=10)


def test_the_target_cap_is_reported_not_silent():
    table = [Listener("127.0.0.1", 1000 + i, i + 1) for i in range(10)]
    plan = build_plan(table, max_targets=4)
    assert len(plan.targets) == 4 and plan.truncated is True
    assert [t.port for t in plan.targets] == [1000, 1001, 1002, 1003]
    assert build_plan(table, max_targets=10).truncated is False


def test_two_different_owners_of_one_destination_are_ambiguous_not_guessed():
    plan = build_plan([Listener("0.0.0.0", 80, 10), Listener("127.0.0.1", 80, 20)], max_targets=10)
    (target,) = plan.targets
    assert target.pid is None and target.ambiguous_owner is True
    assert build_plan([Listener("0.0.0.0", 80, None)], max_targets=10).targets[0].pid is None


# ------------------------------------------------------------------ attribution
def test_attribution_never_guesses():
    info = ProcessInfo("svc.exe", "C:\\svc\\svc.exe")
    assert tt.attribution(42, False, lambda pid: info) == ("attributed", info)
    assert tt.attribution(42, False, lambda pid: None) == ("not_found", None)
    assert tt.attribution(None, False, lambda pid: info) == ("unavailable", None)
    assert tt.attribution(42, True, lambda pid: info) == ("unavailable", None)


@pytest.mark.skipif(sys.platform != "win32", reason="uses the Windows listener table")
def test_own_process_is_resolved_and_system_pids_are_not():
    assert tt.os_process_info(os.getpid()).exe_path.lower().endswith("python.exe") or tt.os_process_info(os.getpid()) is not None
    assert tt.os_process_info(4) is None and tt.os_process_info(0) is None and tt.os_process_info(-5) is None


# ------------------------------------------------------------------ the OS table (read only, nothing is connected)
@pytest.mark.skipif(sys.platform != "win32", reason="uses the Windows listener table")
def test_the_real_listener_table_is_readable_and_well_formed():
    table = tt.os_listeners()
    assert table and all(isinstance(l.port, int) and 0 < l.port <= 65535 for l in table)
    assert all(l.pid is None or isinstance(l.pid, int) for l in table)


@pytest.mark.skipif(sys.platform != "win32", reason="uses the Windows listener table")
def test_a_listener_opened_by_the_test_is_found_with_its_owner():
    import socket
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        mine = [l for l in tt.os_listeners() if l.port == port]
    assert mine == [Listener("127.0.0.1", port, os.getpid())]


def test_an_unreadable_table_is_a_fixed_code_error(monkeypatch):
    def broken(family):
        raise EnumerationError("table_unreadable")
    monkeypatch.setattr(tt, "_read_table", broken)
    with pytest.raises(EnumerationError) as failure:
        tt.os_listeners()
    assert failure.value.code == "table_unreadable"


def test_unexpected_os_errors_become_the_same_fixed_error(monkeypatch):
    def broken(family):
        raise OSError("secret detail C:\\private")
    monkeypatch.setattr(tt, "_read_table", broken)
    with pytest.raises(EnumerationError) as failure:
        tt.os_listeners()
    assert "secret" not in str(failure.value) and failure.value.code == "table_unreadable"
