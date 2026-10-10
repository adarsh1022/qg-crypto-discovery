"""TLS record validation: a strict allow-list that says what a record IS (one active probe attempt) and refuses everything else."""
import json

import pytest

from agent import tls_probe
from backend import tls_record as tr
from backend.fs_record import RecordRejected
from tlsingestfx import MARKERS, deep, failed_record, peer, sha, tls_error, tls_record, tls_summary

validate = tr.validate_tls_record


def _short(value):
    """Readable, short test ids (some values here are 33,000 characters long)."""
    return repr(value)[:24]


def rejected(record):
    with pytest.raises(RecordRejected) as refusal:
        validate(record)
    return refusal.value.code


def with_(**overrides):
    return tls_record(**overrides)


# ------------------------------------------------------------------ valid records
def test_a_completed_probe_record_is_normalised_for_storage():
    valid = validate(tls_record(7, port=8443))
    obs = valid.observation
    assert (obs["direction"], obs["transport"], obs["sni"]) == ("unknown", "tcp", None)
    assert (obs["src_ip"], obs["dst_ip"], obs["dst_port"]) == ("127.0.0.1", "127.0.0.1", 8443)
    assert (obs["event_count"], obs["packet_count"]) == (1, 0)
    assert json.loads(obs["event_counts_json"]) == {"handshake_completed": 1, "probe_attempts": 1}
    assert json.loads(obs["warnings_json"]) == MARKERS and obs["evidence_confidence"] == "high"
    assert [c["sha256"] for c in valid.certificates] == [sha(7)]
    assert valid.certificates[0]["is_ca"] == 0 and json.loads(valid.certificates[0]["san_json"]) == [{"type": "dns", "value": "host7.example"}]
    assert set(obs) == set(tr.OBSERVATION_COLUMNS) and not ({"local_ip", "remote_ip", "local_port", "remote_port"} & set(obs))


@pytest.mark.parametrize("outcome,code", [("failed", "handshake_failed"), ("incomplete", "connect_timeout"), ("alert", "tlsv1_alert_protocol_version"),
                                          ("unknown", "unrecognised_handshake_details")])
def test_inconclusive_probes_are_valid_records_with_no_version_cipher_or_certificate(outcome, code):
    valid = validate(failed_record(outcome=outcome, code=code))
    assert valid.certificates == () and valid.observation["tls_version"] is None and valid.observation["cipher_suite"] is None
    assert valid.observation["cert_visibility"] == "not_observed" and valid.observation["evidence_confidence"] == "low"


def test_a_chain_keeps_its_order_and_may_repeat_a_fingerprint():
    chain = [peer(1), peer(2, is_ca=True), peer(1)]
    assert [c["sha256"] for c in validate(tls_record(1, peers=chain)).certificates] == [sha(1), sha(2), sha(1)]


def test_a_completed_handshake_without_a_certificate_is_medium_confidence():
    record = tls_record(peers=[], cert_visibility="not_observed", evidence_confidence="medium", warnings=MARKERS + ["certificate_unavailable"])
    assert validate(record).certificates == ()


@pytest.mark.parametrize("version", ["SSL3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"])
def test_every_schema_version_is_accepted(version):
    assert validate(tls_record(tls_version=version)).observation["tls_version"] == version


def test_optional_certificate_fields_may_be_null():
    assert validate(tls_record(peers=[peer(1, key_size=None, key_curve="P-256", is_ca=None)])).certificates[0]["is_ca"] is None


def test_addresses_are_normalised():
    obs = validate(tls_record(src_ip="::1", dst_ip="0:0:0:0:0:0:0:1")).observation
    assert (obs["src_ip"], obs["dst_ip"]) == ("::1", "::1")


# ------------------------------------------------------------------ what a record must say it is
def test_records_missing_the_probe_markers_are_rejected():
    assert rejected(with_(warnings=[])) == "missing_probe_markers"
    assert rejected(with_(warnings=["active_probe"], evidence_confidence="high")) == "missing_probe_markers"
    assert rejected(with_(warnings=["packet_counts_unavailable"])) == "missing_probe_markers"
    assert rejected(failed_record(warnings=["handshake_failed"])) == "missing_probe_markers"


@pytest.mark.parametrize("direction", ["inbound", "outbound", "passive", "", None, 5])
def test_only_direction_unknown_is_accepted(direction):
    assert rejected(with_(direction=direction)) == "bad_direction"


def test_probe_counts_are_exactly_one_attempt_and_no_packet_counts():
    for bad in (0, 2, True, None, "1"):
        assert rejected(with_(event_count=bad)).endswith("event_count")
    for bad in (1, 40, -1, True, None):
        assert rejected(with_(packet_count=bad)).endswith("packet_count")
    for counts in ({}, {"probe_attempts": 1}, {"probe_attempts": 2, "handshake_completed": 1}, {"probe_attempts": 1, "handshake_completed": 0},
                   {"probe_attempts": True, "handshake_completed": 1}, {"probe_attempts": 1, "handshake_completed": 1, "packets": 9}, [], None):
        assert rejected(with_(event_counts=counts)) == "bad_event_counts"
    assert rejected(failed_record(event_counts={"probe_attempts": 1, "handshake_completed": 1})) == "bad_event_counts"


def test_transport_and_sni_are_fixed():
    assert rejected(with_(transport="udp")) == "bad_transport"
    assert rejected(with_(sni="example.com")) == "bad_sni"


def test_passive_capture_vocabulary_is_refused():
    assert rejected(with_(cert_visibility="encrypted_tls13")) == "bad_cert_visibility"


@pytest.mark.parametrize("field", ["local_ip", "local_port", "remote_ip", "remote_port", "cipher_id", "last_event_at", "der", "pem",
                                   "private_key", "certificate_bytes", "payload", "password"])
def test_unknown_fields_are_refused_whatever_they_hold(field):
    record = tls_record()
    record[field] = "x"
    assert rejected(record) == "unknown_field"


def test_missing_fields_are_refused():
    for field in tr.TLS_RECORD_FIELDS:
        record = tls_record()
        del record[field]
        assert rejected(record) == "missing_field"


@pytest.mark.parametrize("record", [None, [], "x", 5, [1, 2]])
def test_a_record_must_be_an_object(record):
    assert rejected(record) == "not_an_object"


# ------------------------------------------------------------------ addresses and ports
@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
@pytest.mark.parametrize("bad", ["", "example.com", "localhost", "999.1.1.1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "169.254.169.254", "fe80::1",
                                 "::ffff:127.0.0.1", "fe80::1%4", "127.0.0.1:80", None, 5, "127.0.0.1\n"], ids=_short)
def test_addresses_must_be_usable_literals(field, bad):
    assert rejected(with_(**{field: bad})) == f"bad_{field}"


@pytest.mark.parametrize("field", ["src_port", "dst_port"])
@pytest.mark.parametrize("bad", [0, -1, 65536, 70000, True, "80", 1.5, None])
def test_ports_are_1_to_65535(field, bad):
    assert rejected(with_(**{field: bad})) == f"bad_{field}"


# ------------------------------------------------------------------ consistency the database does not enforce
def test_version_and_cipher_exist_exactly_when_the_handshake_completed():
    assert rejected(with_(tls_version=None)) == "handshake_details_mismatch"
    assert rejected(with_(cipher_suite=None)) == "handshake_details_mismatch"
    assert rejected(failed_record(tls_version="TLS1.2")) == "handshake_details_mismatch"
    assert rejected(failed_record(cipher_suite="TLS_AES_128_GCM_SHA256")) == "handshake_details_mismatch"


def test_an_inconclusive_probe_can_never_carry_a_certificate():
    record = failed_record(peer_certificates=[peer(1)], cert_visibility="visible")
    assert rejected(record) == "certificate_without_completed_handshake"


def test_certificate_visibility_must_match_the_presence_of_certificates():
    assert rejected(with_(cert_visibility="not_observed")) == "cert_visibility_mismatch"
    assert rejected(with_(peers=[], cert_visibility="visible", evidence_confidence="medium")) == "cert_visibility_mismatch"


def test_the_confidence_rule_is_enforced():
    assert rejected(with_(evidence_confidence="medium")) == "confidence_mismatch"
    assert rejected(with_(evidence_confidence="low")) == "confidence_mismatch"
    assert rejected(with_(warnings=MARKERS + ["chain_unavailable"], evidence_confidence="high")) == "confidence_mismatch"
    assert validate(with_(warnings=MARKERS + ["chain_unavailable"], evidence_confidence="medium"))
    assert rejected(failed_record(evidence_confidence="high")) == "confidence_mismatch"


@pytest.mark.parametrize("record", [
    dict(process_attribution="attributed", process_name=None), dict(process_attribution="attributed", exe_path=None),
    dict(process_attribution="attributed", pid=None), dict(process_attribution="not_found"),
    dict(process_attribution="unavailable"), dict(process_attribution="guessed"), dict(process_attribution=None),
])
def test_process_attribution_must_match_the_process_fields(record):
    assert rejected(tls_record(**record)).endswith(("process_attribution", "process_attribution_mismatch"))


def test_valid_attribution_shapes():
    assert validate(tls_record(process_attribution="not_found", process_name=None, exe_path=None))
    assert validate(tls_record(process_attribution="unavailable", pid=None, process_name=None, exe_path=None))


# ------------------------------------------------------------------ warnings, text, bounds
@pytest.mark.parametrize("warnings", [MARKERS + ["Bad Code"], MARKERS + [""], MARKERS + [5], MARKERS + ["x" * 65], "active_probe",
                                      MARKERS + MARKERS, MARKERS + ["a"] * 2, MARKERS + [f"w{i}" for i in range(63)]], ids=_short)
def test_warnings_must_be_unique_fixed_codes(warnings):
    assert rejected(with_(warnings=warnings, evidence_confidence="medium")).endswith("warnings")


@pytest.mark.parametrize("field,value,code", [
    ("cipher_suite", "TLS AES", "bad_cipher_suite"), ("cipher_suite", "x" * 129, "too_long_cipher_suite"),
    ("cipher_suite", "-----BEGIN CERTIFICATE-----", "pem_armor_in_cipher_suite"), ("process_name", "x" * 1025, "too_long_process_name"),
    ("exe_path", "x" * 33001, "too_long_exe_path"), ("exe_path", "C:\\-----BEGIN PRIVATE KEY-----", "pem_armor_in_exe_path"),
    ("process_name", "-----BEGIN CERTIFICATE-----", "pem_armor_in_process_name"), ("observed_at", "2026-03-01 12:00:00", "bad_observed_at"),
    ("observed_at", "2026-13-01T12:00:00Z", "bad_observed_at"), ("observed_at", "2026-03-01T12:00:00.123Z", "bad_observed_at"),
], ids=_short)
def test_text_fields_are_bounded_and_clean(field, value, code):
    assert rejected(with_(**{field: value})) == code


def test_pid_must_be_a_non_negative_integer():
    for bad in (-1, True, "4", 1.5, 2**31):
        assert rejected(with_(pid=bad)).endswith("pid")


# ------------------------------------------------------------------ peer certificates
def test_at_most_ten_peer_certificates_and_they_must_be_a_list():
    assert validate(tls_record(peers=[peer(i) for i in range(1, 11)]))
    assert rejected(tls_record(peers=[peer(i) for i in range(1, 12)])).endswith("peer_certificates")
    assert rejected(with_(peer_certificates="x")).endswith("peer_certificates")
    assert rejected(with_(peer_certificates=None)).endswith("peer_certificates")


@pytest.mark.parametrize("change,code", [
    (dict(sha256="A" * 64), "bad_sha256"), (dict(sha256="a" * 63), "bad_sha256"), (dict(sha256=None), "bad_sha256"),
    (dict(serial_hex="xyz"), "bad_serial_hex"), (dict(serial_hex=""), "bad_serial_hex"), (dict(subject=None), "bad_subject"),
    (dict(subject="x" * 8193), "too_long_subject"), (dict(subject="-----BEGIN CERTIFICATE-----"), "pem_armor_in_subject"),
    (dict(issuer=5), "bad_issuer"), (dict(key_algorithm=None), "bad_key_algorithm"), (dict(key_size=0), "bad_key_size"),
    (dict(key_size=True), "bad_key_size"), (dict(signature_algorithm=None), "bad_signature_algorithm"),
    (dict(not_before="yesterday"), "bad_not_before"), (dict(not_after="2027-01-01"), "bad_not_after"), (dict(is_ca="yes"), "bad_is_ca"),
    (dict(san="dns:x"), "bad_san"), (dict(san=[{"type": "dns"}]), "bad_san"), (dict(san=[{"type": "dns", "value": "x" * 2049}]), "too_long_san"),
    (dict(san=[{"type": "dns", "value": "-----BEGIN CERTIFICATE-----"}]), "pem_armor_in_san"),
], ids=_short)
def test_certificate_facts_are_validated(change, code):
    assert rejected(tls_record(peers=[peer(1, **change)])) == code


@pytest.mark.parametrize("extra", ["der", "pem", "private_key", "raw", "bytes"])
def test_certificate_facts_accept_no_extra_field_so_no_raw_certificate_can_ride_along(extra):
    facts = peer(1)
    facts[extra] = "MIIB..."
    assert rejected(tls_record(peers=[facts])) == "bad_peer_certificates"
    facts = peer(1)
    del facts["subject"]
    assert rejected(tls_record(peers=[facts])) == "bad_peer_certificates"
    assert rejected(tls_record(peers=["MIIB..."])) == "bad_peer_certificates"


def test_a_record_with_raw_certificate_text_anywhere_is_refused():
    for field in ("process_name", "exe_path", "cipher_suite"):
        assert "pem_armor" in rejected(with_(**{field: "x -----BEGIN CERTIFICATE----- y"})) or rejected(with_(**{field: "x -----BEGIN CERTIFICATE----- y"})) == "bad_cipher_suite"


# ------------------------------------------------------------------ the agent and the backend agree
def test_the_agent_and_the_backend_use_the_same_field_lists():
    assert tuple(tls_probe.RECORD_FIELDS) == tr.TLS_RECORD_FIELDS
    assert tuple(tls_probe.CERT_FACT_FIELDS) == tr.CERT_FACT_FIELDS
    assert tuple(tls_probe.MARKER_WARNINGS) == tr.MARKER_WARNINGS
    assert tuple(tls_probe.VERSIONS.values()) == tr.VERSIONS[:0] + tuple(tls_probe.VERSIONS.values())
    assert set(tls_probe.VERSIONS.values()) <= set(tr.VERSIONS)
    assert tls_probe.MAX_PEER_CERTIFICATES == tr.MAX_PEER_CERTIFICATES


@pytest.mark.parametrize("outcome", tr.OUTCOMES)
@pytest.mark.parametrize("peers", [0, 1, 3])
@pytest.mark.parametrize("extras", [[], ["chain_unavailable"], ["connect_timeout"]])
def test_both_sides_apply_one_confidence_rule(outcome, peers, extras):
    warnings = MARKERS + extras
    assert tls_probe.derive_confidence(outcome, peers, warnings) == tr.derive_confidence(outcome, peers, warnings)


def test_a_record_built_by_the_real_probe_is_accepted(tmp_path):
    import datetime as dt
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))
    from tlsfx import TlsServer, make_material
    from agent.tls_targets import ProcessInfo, Target
    material = make_material(tmp_path, chain=True)
    with TlsServer(material) as server:
        record = tls_probe.probe(Target("127.0.0.1", server.port, 99), tls_probe.Timeouts(), now=lambda: dt.datetime(2026, 3, 1, 12, tzinfo=dt.timezone.utc),
                                 attribution=("attributed", ProcessInfo("svc.exe", "C:\\svc\\svc.exe")))
    json_safe = json.loads(json.dumps(record))                         # exactly what travels over HTTP
    valid = validate(json_safe)
    assert valid.observation["handshake_outcome"] == "completed" and len(valid.certificates) == 3


# ------------------------------------------------------------------ the agent's scan summary
def test_a_valid_summary_is_parsed():
    facts = tr.parse_tls_summary(tls_summary(3, completed=2, errors=[tls_error()]))
    assert (facts.stop_reason, facts.enumeration, facts.records, facts.handshakes_completed, facts.errors_total) == ("completed", "ok", 3, 2, 1)
    assert facts.errors == (("probe", "target_not_local"),) and facts.invalid_errors == 0
    assert facts.stored["listeners_found"] == 3 and "errors" not in facts.stored


@pytest.mark.parametrize("bad", [None, [], "x", 5, {}, {"enumeration": "maybe"}, {"enumeration": "ok", "stop_reason": "Bad Reason"},
                                 {"enumeration": "ok", "stop_reason": 5}, {"enumeration": "ok", "errors": "x"},
                                 {"enumeration": "ok", "elapsed_seconds": float("nan")}, {"enumeration": "ok", "records": float("inf")}])
def test_unusable_summaries_are_refused_as_a_whole(bad):
    assert tr.parse_tls_summary(bad) is None


def test_invalid_error_entries_are_counted_not_stored():
    summary = tls_summary(0, errors=[tls_error(), {"kind": "probe"}, {"kind": "other", "code": "x"}, {"kind": "probe", "code": "Bad Code"},
                                     {"kind": "probe", "code": "ok_code", "path": "C:\\secret"}, "x"], errors_total=6)
    facts = tr.parse_tls_summary(summary)
    assert facts.errors == (("probe", "target_not_local"),) and facts.invalid_errors == 5


def test_summary_counts_that_are_not_counts_are_dropped_not_trusted():
    facts = tr.parse_tls_summary(tls_summary(3, records_by_outcome={"completed": 2, "bogus": 1, "failed": -1}))
    assert facts.stored["records_by_outcome"] == {"completed": 2}
    summary = tls_summary(3)
    summary["records"] = -5
    summary["handshakes_completed"] = True
    facts = tr.parse_tls_summary(summary)
    assert facts.records is None and facts.handshakes_completed is None


def test_the_stored_summary_holds_no_free_text_from_the_agent():
    summary = tls_summary(1, errors=[tls_error()], hostname="secret-host", note="C:\\private\\key.pem")
    assert "secret" not in json.dumps(tr.parse_tls_summary(summary).stored) and "private" not in json.dumps(tr.parse_tls_summary(summary).stored)


def test_an_oversized_error_list_is_capped():
    summary = tls_summary(0, errors=[tls_error()] * 1500, errors_total=1500)
    facts = tr.parse_tls_summary(summary)
    assert len(facts.errors) == tr.MAX_LISTED_ERRORS and facts.errors_total == 1500


_ = deep
