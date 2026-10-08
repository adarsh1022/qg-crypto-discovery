"""Pure record-building: schema contract, chain roles, validity, confidence."""
import datetime as dt
import json

import pytest

import certgen
import pemgen
from agent import observations
from agent.cert_file import parse_cert_bytes
from agent.observations import (ALL_STATUSES, RECORD_FIELDS, blank_record, chain_role, evidence_confidence,
                                file_record, iso_utc, records_from_file_parse)
from agent.x509_parse import parse_certificate
from test_handbuilt import build_v1, rsa_spki, PADDED_MODULUS
from treegen import NOW

UTC = dt.timezone.utc
DAY = dt.timedelta(days=1)


def records_for(data, filename="x.pem", now=NOW, expiring_days=30, root="C:\\r"):
    parsed = parse_cert_bytes(data, filename_hint=filename)
    return records_from_file_parse(f"{root}\\{filename}", filename, root, parsed, now, expiring_days)


def cert_with_dates(nb, na, cn="dates"):
    return certgen.make(certgen.name(cn), nb=nb, na=na)


def test_schema_contract_is_frozen():
    # Any change to the record schema must be a conscious edit of this list (and the backend).
    assert RECORD_FIELDS == (
        "path", "filename", "scan_root", "format", "discovered_at",
        "sha256", "serial_hex", "subject", "issuer", "san",
        "chain_index", "chain_total", "chain_role",
        "key_algorithm", "key_size", "key_curve", "signature_algorithm",
        "not_before", "not_after", "days_to_expiry", "validity_status", "not_yet_valid",
        "is_ca", "warnings",
        "parse_status", "detail", "access_error", "evidence_confidence",
        "extension_mismatch", "duplicate_in_scan",
        "owning_process")
    assert "file_size" not in RECORD_FIELDS                       # decision: size stays out of records


def test_every_record_has_exactly_the_schema_keys_in_order():
    samples = [records_for(pemgen.pem_encode(pemgen.der_of("key_p256"))),
               records_for(b"junk"), records_for(b""), records_for(pemgen.pem_encode(b"not der")),
               [blank_record("p", "f", "r", "pem", "t")], [file_record("p", "f", "r", "pem", "t", "skipped", "x")]]
    for batch in samples:
        for record in batch:
            assert tuple(record) == RECORD_FIELDS


def test_records_are_plain_json_with_no_bytes():
    for rec in records_for(pemgen.pem_encode(certgen.CASES["san_dns"][0]())):
        text = json.dumps(rec)
        assert json.loads(text) == rec
    assert iso_utc(NOW) == "2025-06-01T12:00:00Z"


def test_ok_record_maps_every_certificate_field():
    der = certgen.CASES["san_dns"][0]()
    info = parse_certificate(der)
    (rec,) = records_for(pemgen.pem_encode(der), "web.pem", root="C:\\certs")
    assert (rec["path"], rec["filename"], rec["scan_root"]) == ("C:\\certs\\web.pem", "web.pem", "C:\\certs")
    assert rec["format"] == "pem" and rec["discovered_at"] == "2025-06-01T12:00:00Z"
    assert rec["sha256"] == info.sha256 and rec["serial_hex"] == info.serial_hex
    assert (rec["subject"], rec["issuer"]) == (info.subject, info.issuer)
    assert rec["san"] == [{"type": "dns", "value": "example.com"}, {"type": "dns", "value": "*.example.org"}]
    assert (rec["chain_index"], rec["chain_total"]) == (0, 1)
    assert (rec["key_algorithm"], rec["key_size"], rec["key_curve"]) == ("RSA", 2048, None)
    assert rec["signature_algorithm"] == "sha256WithRSAEncryption"
    assert (rec["not_before"], rec["not_after"]) == ("2024-01-01T00:00:00Z", "2034-01-01T00:00:00Z")
    assert (rec["parse_status"], rec["detail"], rec["access_error"]) == ("ok", None, None)
    assert (rec["evidence_confidence"], rec["extension_mismatch"], rec["duplicate_in_scan"]) == ("high", False, False)
    assert rec["owning_process"] is None and rec["warnings"] == []


# ---------------------------------------------------------------- validity at the discovery time
@pytest.mark.parametrize("name,nb,na,days,status,future", [
    ("valid", NOW - DAY, NOW + 365 * DAY, 365, "valid", False),
    ("exactly_31_days", NOW - DAY, NOW + 31 * DAY, 31, "valid", False),
    ("exactly_30_days", NOW - DAY, NOW + 30 * DAY, 30, "expiring", False),
    ("one_day_left", NOW - DAY, NOW + DAY, 1, "expiring", False),
    ("expired_yesterday", NOW - 400 * DAY, NOW - DAY, -1, "expired", False),
    ("expired_long_ago", NOW - 900 * DAY, NOW - 100 * DAY, -100, "expired", False),
    ("not_yet_valid", NOW + 10 * DAY, NOW + 400 * DAY, 400, "valid", True),
])
def test_validity_fields(name, nb, na, days, status, future):
    (rec,) = records_for(pemgen.pem_encode(cert_with_dates(nb, na, name)))
    assert (rec["days_to_expiry"], rec["validity_status"], rec["not_yet_valid"]) == (days, status, future)


def test_expiring_threshold_is_configurable():
    der = pemgen.pem_encode(cert_with_dates(NOW - DAY, NOW + 40 * DAY))
    assert records_for(der, expiring_days=30)[0]["validity_status"] == "valid"
    assert records_for(der, expiring_days=45)[0]["validity_status"] == "expiring"


# ---------------------------------------------------------------- chain roles and positions
def _chain():
    root = certgen.make(certgen.name("Root"), "p256", bc=(True, None))
    inter = certgen.make(certgen.name("Inter"), "p384", sign_kind="p256", issuer=certgen.name("Root"), bc=(True, 0))
    leaf = certgen.make(certgen.name("leaf"), "rsa2048", sign_kind="p384", issuer=certgen.name("Inter"))
    leaf_not_ca = certgen.make(certgen.name("leaf2"), "ed25519", sign_kind="p384", issuer=certgen.name("Inter"),
                               bc=(False, None))
    return root, inter, leaf, leaf_not_ca


def test_chain_roles():
    root, inter, leaf, leaf_not_ca = _chain()
    assert [chain_role(parse_certificate(d)) for d in (root, inter, leaf, leaf_not_ca)] == [
        "self_signed", "ca", "leaf", "leaf"]


def test_bundle_positions_and_roles_within_one_file():
    root, inter, leaf, _ = _chain()
    recs = records_for(b"".join(pemgen.pem_encode(d) for d in (leaf, inter, root)))
    assert [(r["chain_index"], r["chain_total"], r["chain_role"]) for r in recs] == [
        (0, 3, "leaf"), (1, 3, "ca"), (2, 3, "self_signed")]


# ---------------------------------------------------------------- confidence and failures
def test_evidence_confidence_mapping():
    assert evidence_confidence("ok", []) == "high"
    assert evidence_confidence("ok", ["serial_not_positive"]) == "medium"
    for status in ALL_STATUSES:
        if status != "ok":
            assert evidence_confidence(status, []) == "low"


def test_certificate_with_warnings_is_medium_confidence():
    unknown_key = build_v1(rsa_spki(PADDED_MODULUS), sig_oid="2a030405")
    (rec,) = records_for(unknown_key, "odd.der")
    assert rec["parse_status"] == "ok" and rec["evidence_confidence"] == "medium"
    assert "unknown_signature_algorithm" in rec["warnings"]


def test_failed_entry_in_a_bundle_keeps_position_and_has_no_certificate_fields():
    good = pemgen.pem_encode(pemgen.der_of("key_p256"))
    bad = b"-----BEGIN CERTIFICATE-----\nAAA*AAAA\n-----END CERTIFICATE-----\n"
    recs = records_for(good + bad + good)
    assert [r["parse_status"] for r in recs] == ["ok", "malformed", "ok"]
    broken = recs[1]
    assert (broken["chain_index"], broken["chain_total"], broken["detail"]) == (1, 3, "pem_bad_base64")
    assert broken["evidence_confidence"] == "low"
    for field in ("sha256", "subject", "issuer", "not_after", "days_to_expiry", "validity_status", "chain_role"):
        assert broken[field] is None


@pytest.mark.parametrize("data,status,detail", [
    (b"", "no_certificate", "empty_file"),
    (b"hello", "malformed", "unrecognized_content"),
    (pemgen.pem_encode(b"x", label=b"PRIVATE KEY"), "no_certificate", "no_certificate_block"),
    (b"\xff\xfeA", "unsupported", "utf16_text_unsupported"),
])
def test_file_level_records(data, status, detail):
    (rec,) = records_for(data)
    assert (rec["parse_status"], rec["detail"]) == (status, detail)
    assert rec["sha256"] is None and rec["chain_index"] is None and rec["evidence_confidence"] == "low"


def test_extension_mismatch_is_carried_into_records():
    der = pemgen.der_of("key_p256")
    assert records_for(der, "oops.pem")[0]["extension_mismatch"] is True
    assert records_for(der, "fine.der")[0]["extension_mismatch"] is False
    assert records_for(b"", "empty.pem")[0]["extension_mismatch"] is False


def test_safe_text_escapes_only_unencodable_characters():
    from agent.observations import safe_text
    for untouched in ("", "plain C:\\dir\\file.pem", "ünï 测试 😀.pem", "back\\slash and \\u0041 text"):
        assert safe_text(untouched) == untouched
    assert safe_text("a\ud800b") == "a\\ud800b"
    assert safe_text("\udc80\udfff") == "\\udc80\\udfff"
    assert safe_text("😀\ud83d") == "😀\\ud83d"            # a valid pair stays; a lone half is escaped
    once = safe_text("x\ud800y")
    assert safe_text(once) == once                           # idempotent
    for s in ("a\ud800b", "\udc80", "ok", "😀"):
        safe_text(s).encode("utf-8")                         # always strictly encodable


def test_record_metadata_is_sanitised_at_construction():
    rec = file_record("C:\\r\\bad\ud800.pem", "bad\ud800.pem", "C:\\r\udc80", "pem", "t", "malformed", "x")
    assert (rec["path"], rec["filename"], rec["scan_root"]) == (
        "C:\\r\\bad\\ud800.pem", "bad\\ud800.pem", "C:\\r\\udc80")
    json.dumps(rec, ensure_ascii=False).encode("utf-8")
    assert blank_record("p\ud800", "f\ud800", "r\ud800", "pem", "t")["path"] == "p\\ud800"


def test_file_record_helper():
    rec = file_record("p", "f.pem", "r", "unknown", "2025-01-01T00:00:00Z", "access_denied", "read_failed",
                      "PermissionError:WinError 5")
    assert rec["parse_status"] == "access_denied" and rec["access_error"] == "PermissionError:WinError 5"
    assert observations.ALL_STATUSES.count("ok") == 1
