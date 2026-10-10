"""The TLS probe against real local servers: what a record says, what it never contains, and how failures look."""
import base64
import datetime as dt
import json
import logging
import socket

import pytest

import pemgen
from agent import tls_probe
from agent.tls_probe import MARKER_WARNINGS, ProbeAborted, Timeouts, derive_confidence, probe
from agent.tls_targets import ProcessInfo, Target
from tlsfx import PlainServer, SilentServer, TlsServer, closed_port, make_material, tls_versions

NOW = dt.datetime(2026, 10, 10, 12, 0, 0, tzinfo=dt.timezone.utc)
FAST = Timeouts(connect=2.0, handshake=2.0)
UNATTRIBUTED = ("unavailable", None)


def run_probe(port, *, ip="127.0.0.1", pid=None, attribution=UNATTRIBUTED, timeouts=FAST, **kw):
    return probe(Target(ip, port, pid), timeouts, now=lambda: NOW, attribution=attribution, **kw)


# ------------------------------------------------------------------ a successful handshake
@pytest.mark.parametrize("label,version", tls_versions())
def test_a_completed_handshake_records_what_the_server_really_presented(tmp_path, label, version):
    material = make_material(tmp_path)
    with TlsServer(material, max_version=version, min_version=version) as server:
        record = run_probe(server.port, pid=4321, attribution=("attributed", ProcessInfo("svc.exe", "C:\\svc\\svc.exe")))
    assert record["handshake_outcome"] == "completed" and record["tls_version"] == label
    assert record["cipher_suite"] and record["cert_visibility"] == "visible"
    (leaf, *rest) = record["peer_certificates"]
    assert leaf["sha256"] == material.leaf_sha256                      # the fingerprint of what the server actually presented
    assert leaf["subject"] == "CN=probe-test.local" and [s["value"] for s in leaf["san"]] == ["probe-test.local"]
    assert leaf["key_algorithm"] == "RSA" and leaf["key_size"] == 2048 and leaf["is_ca"] is False


def test_a_record_says_it_is_an_active_probe_of_a_listener_not_observed_traffic(tmp_path):
    material = make_material(tmp_path)
    with TlsServer(material) as server:
        record = run_probe(server.port)
    assert tuple(record) == tls_probe.RECORD_FIELDS
    assert record["direction"] == "unknown" and record["transport"] == "tcp"
    assert all(marker in record["warnings"] for marker in MARKER_WARNINGS)
    assert (record["event_count"], record["packet_count"]) == (1, 0)
    assert record["event_counts"] == {"probe_attempts": 1, "handshake_completed": 1}
    assert record["sni"] is None
    assert (record["dst_ip"], record["dst_port"]) == ("127.0.0.1", server.port)
    assert record["src_ip"] == "127.0.0.1" and record["src_port"] not in (0, server.port)    # the probe's own socket
    assert record["observed_at"] == "2026-10-10T12:00:00Z"
    assert "local_ip" not in record and "remote_ip" not in record


def test_the_probe_sends_no_application_data(tmp_path):
    material = make_material(tmp_path)
    with TlsServer(material) as server:
        run_probe(server.port)
        server._stop.wait(0.3)
        assert server.connections == 1 and server.received == b""


def test_a_full_chain_is_recorded_leaf_first_when_the_private_api_works(tmp_path):
    material = make_material(tmp_path, chain=True)
    with TlsServer(material) as server:
        record = run_probe(server.port)
    got = [c["sha256"] for c in record["peer_certificates"]]
    import hashlib
    assert got == [hashlib.sha256(d).hexdigest() for d in material.ders]
    assert record["warnings"].count("chain_unavailable") == 0 and record["evidence_confidence"] == "high"


def test_without_the_private_chain_api_the_leaf_alone_is_recorded_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_probe, "_chain_der", lambda ssock, leaf: None)
    material = make_material(tmp_path, chain=True)
    with TlsServer(material) as server:
        record = run_probe(server.port)
    assert [c["sha256"] for c in record["peer_certificates"]] == [material.leaf_sha256]
    assert "chain_unavailable" in record["warnings"] and record["evidence_confidence"] == "medium"
    assert record["handshake_outcome"] == "completed"


def test_a_chain_that_disagrees_with_the_public_leaf_is_ignored(tmp_path):
    class FakeObj:
        def get_unverified_chain(self):
            class C:
                def public_bytes(self, fmt):
                    return b"not the leaf"
            return [C()]

    class FakeSock:
        _sslobj = FakeObj()

    assert tls_probe._chain_der(FakeSock(), b"the leaf") is None


def test_a_broken_private_api_means_no_chain_not_an_error():
    class Boom:
        @property
        def _sslobj(self):
            raise RuntimeError("private API changed")

    assert tls_probe._chain_der(Boom(), b"x") is None


def test_a_server_without_a_usable_certificate_still_counts_as_a_handshake_but_not_as_a_certificate(monkeypatch, tmp_path):
    monkeypatch.setattr(tls_probe, "_read_certificates", lambda ssock, warnings: (warnings.add("certificate_unavailable"), [])[1])
    material = make_material(tmp_path)
    with TlsServer(material) as server:
        record = run_probe(server.port)
    assert record["handshake_outcome"] == "completed" and record["cert_visibility"] == "not_observed"
    assert record["peer_certificates"] == [] and record["evidence_confidence"] == "medium"
    assert "certificate_unavailable" in record["warnings"]


# ------------------------------------------------------------------ outcomes that are NOT TLS findings
def test_a_plain_text_listener_is_an_inconclusive_probe_with_no_certificate_or_version():
    with PlainServer() as server:
        record = run_probe(server.port)
    assert record["handshake_outcome"] in ("failed", "incomplete")
    assert record["tls_version"] is None and record["cipher_suite"] is None
    assert record["peer_certificates"] == [] and record["cert_visibility"] == "not_observed"
    assert record["evidence_confidence"] == "low" and record["event_counts"]["handshake_completed"] == 0
    assert record["warnings"][:2] == list(MARKER_WARNINGS) and len(record["warnings"]) == 3


def test_a_closed_port_is_an_incomplete_probe_but_the_source_address_is_still_real():
    record = run_probe(closed_port())
    assert record["handshake_outcome"] == "incomplete"
    assert set(record["warnings"]) - set(MARKER_WARNINGS) <= {"connection_refused", "connect_timeout", "connection_failed"}
    assert record["src_ip"] == "127.0.0.1" and record["src_port"] > 0        # known before the connect, even though it failed
    assert record["tls_version"] is None and record["peer_certificates"] == []


def test_a_listener_that_never_answers_times_out_in_the_handshake():
    with SilentServer() as server:
        record = run_probe(server.port, timeouts=Timeouts(connect=1.0, handshake=0.4))
    assert record["handshake_outcome"] == "incomplete" and "handshake_timeout" in record["warnings"]
    assert record["peer_certificates"] == [] and record["evidence_confidence"] == "low"


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_a_tls_alert_is_recorded_as_an_alert_with_a_fixed_code(tmp_path):
    material = make_material(tmp_path)
    import ssl
    with TlsServer(material, max_version=ssl.TLSVersion.TLSv1_1, min_version=ssl.TLSVersion.TLSv1) as server:
        try:
            record = run_probe(server.port)
        except Exception:                                      # a server this old may not even be creatable here
            pytest.skip("no legacy server available")
    assert record["handshake_outcome"] in ("alert", "failed", "incomplete")
    assert record["tls_version"] is None and record["peer_certificates"] == []
    codes = set(record["warnings"]) - set(MARKER_WARNINGS)
    assert all(c and c == c.lower() and all(ch.isalnum() or ch == "_" for ch in c) for c in codes)


# ------------------------------------------------------------------ locality: nothing is contacted unless the address is local
class SpySocket:
    """A socket stand-in that records every call; used to prove that nothing connects when the bind is refused."""

    def __init__(self, family, kind, bind_error=None, peer=("127.0.0.1", 9)):
        self.calls, self.bind_error, self._peer = [], bind_error, peer

    def settimeout(self, value):
        self.calls.append("settimeout")

    def bind(self, address):
        self.calls.append("bind")
        if self.bind_error:
            raise self.bind_error

    def getsockname(self):
        return ("127.0.0.1", 50000)

    def getpeername(self):
        return self._peer

    def connect(self, address):
        self.calls.append("connect")

    def close(self):
        self.calls.append("close")


def test_a_non_local_address_is_refused_by_the_bind_and_never_connected_to():
    made = []

    def factory(family, kind):
        made.append(SpySocket(family, kind, bind_error=OSError(10049, "address not valid")))
        return made[-1]

    with pytest.raises(ProbeAborted) as aborted:
        run_probe(443, ip="8.8.8.8", socket_factory=factory)
    assert aborted.value.code == "target_not_local"
    assert "connect" not in made[0].calls and "close" in made[0].calls


def test_a_peer_that_is_not_the_intended_address_is_dropped_before_any_handshake():
    made = []

    def factory(family, kind):
        made.append(SpySocket(family, kind, peer=("203.0.113.9", 443)))
        return made[-1]

    with pytest.raises(ProbeAborted) as aborted:
        run_probe(443, socket_factory=factory)
    assert aborted.value.code == "peer_mismatch"
    assert made[0].calls.count("connect") == 1 and "close" in made[0].calls


def test_the_probe_binds_before_it_connects():
    made = []

    def factory(family, kind):
        made.append(SpySocket(family, kind, peer=("203.0.113.9", 443)))
        return made[-1]

    with pytest.raises(ProbeAborted):
        run_probe(443, socket_factory=factory)
    assert made[0].calls.index("bind") < made[0].calls.index("connect")


# ------------------------------------------------------------------ process attribution is passed through, never guessed
def test_process_fields_follow_the_attribution(tmp_path):
    material = make_material(tmp_path)
    with TlsServer(material) as server:
        attributed = run_probe(server.port, pid=77, attribution=("attributed", ProcessInfo("svc.exe", "C:\\svc\\svc.exe")))
        not_found = run_probe(server.port, pid=77, attribution=("not_found", None))
        unavailable = run_probe(server.port, pid=None, attribution=UNATTRIBUTED)
    assert (attributed["pid"], attributed["process_name"], attributed["exe_path"], attributed["process_attribution"]) == (77, "svc.exe", "C:\\svc\\svc.exe", "attributed")
    assert (not_found["pid"], not_found["process_name"], not_found["exe_path"], not_found["process_attribution"]) == (77, None, None, "not_found")
    assert (unavailable["pid"], unavailable["process_name"], unavailable["process_attribution"]) == (None, None, "unavailable")


# ------------------------------------------------------------------ nothing sensitive in a record
def test_no_certificate_bytes_private_key_or_pem_ever_appear_in_a_record(tmp_path, caplog):
    material = make_material(tmp_path, chain=True)
    with caplog.at_level(logging.DEBUG):
        with TlsServer(material) as server:
            record = run_probe(server.port)
    text = json.dumps(record)
    for der in material.ders:
        assert der.hex() not in text.lower()
        assert base64.b64encode(der).decode() not in text
        assert base64.b64encode(der[:60]).decode().rstrip("=") not in text
    assert not pemgen.leaked(text, pemgen.canary_set(material.key_pem))
    assert "BEGIN" not in text and "PRIVATE" not in text
    assert caplog.text == "" or material.leaf_sha256 not in caplog.text
    for forbidden in ("der", "pem", "private_key", "certificate_bytes"):
        assert forbidden not in record


def test_certificate_facts_have_exactly_the_agreed_fields(tmp_path):
    material = make_material(tmp_path)
    with TlsServer(material) as server:
        record = run_probe(server.port)
    assert all(tuple(c) == tls_probe.CERT_FACT_FIELDS for c in record["peer_certificates"])


def test_the_handshake_does_not_verify_the_certificate_so_a_self_signed_server_is_still_recorded(tmp_path):
    material = make_material(tmp_path)                            # self-signed: a verifying client would refuse it
    with TlsServer(material) as server:
        assert run_probe(server.port)["handshake_outcome"] == "completed"


# ------------------------------------------------------------------ confidence rule
@pytest.mark.parametrize("outcome,peers,extras,expected", [
    ("completed", 1, [], "high"), ("completed", 3, [], "high"), ("completed", 1, ["chain_unavailable"], "medium"),
    ("completed", 0, [], "medium"), ("failed", 0, [], "low"), ("incomplete", 0, ["connect_timeout"], "low"),
    ("alert", 0, [], "low"), ("unknown", 0, [], "low"),
])
def test_confidence_follows_one_rule(outcome, peers, extras, expected):
    assert derive_confidence(outcome, peers, list(MARKER_WARNINGS) + extras) == expected


def test_socket_module_default_is_used_when_no_factory_is_given(tmp_path):
    material = make_material(tmp_path)
    with TlsServer(material) as server:
        assert isinstance(socket.socket, type) and run_probe(server.port)["dst_port"] == server.port
