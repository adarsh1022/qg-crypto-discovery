"""Record validation: the allow-list, consistency rules, raw-material refusal, text safety, agent contract, summary."""
import pytest

from agent import fs_scan, observations, pfx_bridge
from backend import fs_record, safety
from backend.fs_record import RecordRejected, validate_fs_record
from ingestfx import dir_error, failure_record, ok_record, pfx_record, summary


def rejected(record) -> str:
    with pytest.raises(RecordRejected) as info:
        validate_fs_record(record)
    return info.value.code


# ------------------------------------------------------------------ contract with Phase 1
def test_accepted_fields_are_exactly_the_agents_record_fields():
    assert fs_record.FS_RECORD_FIELDS == observations.RECORD_FIELDS


def test_vocabularies_match_the_agent():
    assert fs_record.PARSE_STATUSES == observations.ALL_STATUSES
    assert fs_record.INTEGRITY_WARNING == pfx_bridge.INTEGRITY_WARNING
    assert fs_record.MAX_LISTED_ERRORS == fs_scan.MAX_LISTED_ERRORS
    assert set(fs_record.FORMATS) == {"pem", "der", "pkcs12", "unknown"}


def test_the_test_helpers_build_records_with_exactly_the_agents_fields():
    for record in (ok_record(), pfx_record(), failure_record()):
        assert set(record) == set(observations.RECORD_FIELDS)


def test_a_record_built_by_the_agent_is_accepted():
    from agent.cert_file import parse_cert_bytes
    import datetime as dt
    import pemgen, pfxgen
    leaf = pfxgen.chain()[2]
    parsed = parse_cert_bytes(pemgen.pem_encode(leaf), filename_hint="a.pem")
    record = observations.records_from_file_parse(r"C:\x\a.pem", "a.pem", r"C:\x", parsed,
                                                  dt.datetime(2026, 3, 1, tzinfo=dt.timezone.utc), 30)[0]
    valid = validate_fs_record(record)
    assert valid.certificate["sha256"] == record["sha256"] and valid.observation["format"] == "pem"


# ------------------------------------------------------------------ happy paths
def test_ok_record_splits_into_observation_and_certificate():
    valid = validate_fs_record(ok_record(n=7))
    assert set(valid.certificate) == set(fs_record.CERT_COLUMNS)
    assert set(valid.observation) == set(fs_record.OBSERVATION_COLUMNS)
    assert valid.certificate["sha256"] == valid.observation["sha256"] == "0" * 63 + "7"
    assert valid.certificate["san_json"] == '[{"type":"DNS","value":"host7.example"}]'
    assert valid.observation["not_yet_valid"] == 0 and valid.certificate["is_ca"] == 0


def test_failure_record_has_no_certificate():
    valid = validate_fs_record(failure_record(status="read_error"))
    assert valid.certificate is None and valid.observation["sha256"] is None
    assert valid.observation["parse_status"] == "read_error" and valid.observation["evidence_confidence"] == "low"


def test_unknown_ca_flag_and_key_size_are_allowed():
    valid = validate_fs_record(ok_record(is_ca=None, key_size=None, key_curve="P-256", key_algorithm="EC"))
    assert valid.certificate["is_ca"] is None and valid.certificate["key_size"] is None
    assert valid.certificate["key_curve"] == "P-256"


def test_legitimate_key_metadata_fields_are_not_mistaken_for_raw_material():
    for name in ("key_algorithm", "key_size", "key_curve"):
        assert name in fs_record.FS_RECORD_FIELDS and not safety.is_raw_material_name(name)
    assert validate_fs_record(ok_record(key_algorithm="RSA", key_size=4096)).certificate["key_size"] == 4096


def test_agent_warnings_are_kept_verbatim():
    valid = validate_fs_record(ok_record(warnings=["serial_not_positive", "trailing_data_after_certificate"],
                                         evidence_confidence="medium"))
    assert valid.observation["warnings_json"] == '["serial_not_positive","trailing_data_after_certificate"]'


# ------------------------------------------------------------------ shape
@pytest.mark.parametrize("bad", [None, [], "record", 5, b"bytes", ()])
def test_non_objects_are_rejected(bad):
    assert rejected(bad) == "not_an_object"


@pytest.mark.parametrize("field", fs_record.FS_RECORD_FIELDS)
def test_every_missing_field_is_rejected(field):
    record = ok_record()
    del record[field]
    assert rejected(record) == "missing_field"


@pytest.mark.parametrize("extra", ["der", "pem", "raw", "private_key", "privatekey", "key_material", "secret", "password",
                                   "certificate", "pfx", "file_size", "anything_else", "DER"])
def test_unknown_fields_are_rejected_so_raw_material_cannot_ride_along(extra):
    record = ok_record()
    record[extra] = "x"
    assert rejected(record) == "unknown_field"
    record[extra] = b"\x30\x82\x01\x00"
    assert rejected(record) == "unknown_field"


def test_non_string_keys_are_rejected():
    record = ok_record()
    record[5] = "x"
    assert rejected(record) == "unknown_field"


# ------------------------------------------------------------------ field rules
@pytest.mark.parametrize("field, value", [
    ("format", "jks"), ("format", None), ("parse_status", "weird"), ("evidence_confidence", "certain"),
    ("chain_role", "root"), ("validity_status", "fine"), ("path", ""), ("path", 5), ("path", None), ("filename", ""),
    ("scan_root", None), ("discovered_at", "yesterday"), ("discovered_at", "2026-02-30T00:00:00Z"),
    ("discovered_at", "2026-03-01T12:00:00+00:00"), ("not_before", "2025"), ("not_after", None),
    ("sha256", "A" * 64), ("sha256", "a" * 63), ("sha256", "g" * 64), ("sha256", None), ("sha256", 5),
    ("serial_hex", ""), ("serial_hex", "xyz"), ("subject", None), ("subject", 5), ("issuer", None),
    ("key_algorithm", None), ("signature_algorithm", None), ("key_size", 0), ("key_size", -1), ("key_size", True),
    ("key_size", "2048"), ("key_size", 2.0), ("days_to_expiry", "5"), ("days_to_expiry", 10**9), ("days_to_expiry", None),
    ("not_yet_valid", 0), ("not_yet_valid", None), ("is_ca", 1), ("extension_mismatch", 1), ("extension_mismatch", None),
    ("duplicate_in_scan", "no"), ("chain_index", -1), ("chain_index", True), ("chain_total", "3"),
    ("san", {}), ("san", "x"), ("san", [{"type": "DNS"}]), ("san", [{"type": "DNS", "value": 5}]),
    ("san", [{"type": "DNS", "value": "a", "extra": "b"}]), ("san", ["a"]), ("warnings", "x"), ("warnings", [5]),
    ("warnings", ["Has Spaces"]), ("warnings", ["x" * 65]), ("warnings", None), ("access_error", "boom"),
    ("access_error", "PermissionError:WinError five"), ("access_error", 5), ("detail", 5),
    ("owning_process", {"pid": 4}), ("owning_process", "explorer"),
])
def test_bad_field_values_are_rejected(field, value):
    record = ok_record()
    record[field] = value
    rejected(record)


def test_rejection_codes_are_fixed_identifiers_and_never_contain_record_content():
    secret = "SuperSecretMarker123"
    for field, value in (("path", 5), ("subject", 5), ("format", secret), ("sha256", secret), ("detail", 5),
                         ("warnings", [secret]), ("access_error", secret), ("discovered_at", secret)):
        record = ok_record()
        record[field] = value
        code = rejected(record)
        assert secret not in code and code.replace("_", "").isalnum() and code.islower()


def test_lengths_are_capped():
    assert rejected(ok_record(path="C:\\" + "a" * 33000)) == "too_long_path"
    assert rejected(ok_record(subject="CN=" + "a" * 9000)) == "too_long_subject"
    assert rejected(ok_record(san=[{"type": "DNS", "value": "a"}] * 501)) == "bad_san"
    assert rejected(ok_record(san=[{"type": "DNS", "value": "a" * 2049}])) == "too_long_san"
    assert rejected(ok_record(warnings=["w"] * 65)) == "bad_warnings"
    assert rejected(failure_record(detail="d" * 301)) == "too_long_detail"


# ------------------------------------------------------------------ cross-field consistency
def test_failure_records_may_not_carry_certificate_facts():
    for field, value in (("sha256", "a" * 64), ("subject", "CN=x"), ("chain_role", "leaf"), ("not_after", "2027-01-01T00:00:00Z"),
                         ("validity_status", "valid"), ("days_to_expiry", 3), ("not_yet_valid", False), ("san", []),
                         ("key_size", 2048), ("is_ca", False), ("key_curve", "P-256")):
        assert rejected(failure_record(**{field: value})) == "failure_with_certificate_fields", field


def test_failure_records_must_have_low_confidence():
    assert rejected(failure_record(evidence_confidence="high")) == "failure_confidence_not_low"
    assert rejected(failure_record(evidence_confidence="medium")) == "failure_confidence_not_low"


def test_pkcs12_records_may_not_claim_a_chain_position():
    assert rejected(pfx_record(chain_index=0)) == "pkcs12_chain_index"
    assert validate_fs_record(pfx_record()).observation["chain_index"] is None


def test_pkcs12_records_that_are_failures_also_have_no_chain_position():
    assert rejected(failure_record(format="pkcs12", chain_index=2)) == "pkcs12_chain_index"


def test_integrity_warning_cannot_coexist_with_high_confidence():
    warning = ["pkcs12_integrity_not_verified"]
    assert rejected(pfx_record(warnings=warning, evidence_confidence="high")) == "integrity_warning_with_high_confidence"
    valid = validate_fs_record(pfx_record(warnings=warning, evidence_confidence="medium"))
    assert valid.observation["warnings_json"] == '["pkcs12_integrity_not_verified"]'
    assert validate_fs_record(pfx_record(warnings=warning, evidence_confidence="medium")).observation["chain_index"] is None


# ------------------------------------------------------------------ text safety
ARMOR = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"


@pytest.mark.parametrize("field", ["path", "filename", "scan_root", "subject", "issuer", "key_algorithm",
                                   "signature_algorithm", "key_curve", "detail"])
def test_pem_armor_in_any_text_field_is_rejected(field):
    record = ok_record() if field != "detail" else failure_record()
    record[field] = "x " + ARMOR
    assert rejected(record) == f"pem_armor_in_{field}"


def test_pem_armor_in_san_is_rejected():
    assert rejected(ok_record(san=[{"type": "DNS", "value": ARMOR}])) == "pem_armor_in_san"
    assert rejected(ok_record(san=[{"type": ARMOR, "value": "a"}])) == "pem_armor_in_san"


def test_private_key_armor_is_refused_too():
    assert rejected(ok_record(subject="-----BEGIN PRIVATE KEY-----")) == "pem_armor_in_subject"
    assert rejected(ok_record(subject="-----END RSA PRIVATE KEY-----")) == "pem_armor_in_subject"


def test_binary_values_are_rejected_in_every_text_field():
    for field in ("path", "filename", "scan_root", "subject", "issuer", "key_algorithm", "signature_algorithm",
                  "serial_hex", "sha256", "discovered_at", "not_before"):
        record = ok_record()
        record[field] = b"\x30\x82\x01\x0a"
        rejected(record)


def test_lone_surrogates_and_nul_are_made_safe_not_rejected():
    valid = validate_fs_record(ok_record(path="C:\\odd\\bad\ud800name.pem", subject="CN=nul\x00here"))
    path = valid.observation["path"]
    assert "\\ud800" in path and "\ud800" not in path
    path.encode("utf-8")                                              # strict UTF-8 works
    assert "\x00" not in valid.certificate["subject"] and "\\x00" in valid.certificate["subject"]


def test_non_bmp_and_unicode_text_is_kept_intact():
    path = "C:\\证书\\ключ-😀\\server.pem"
    valid = validate_fs_record(ok_record(path=path, subject="CN=Zoë 😀"))
    assert valid.observation["path"] == path and valid.certificate["subject"] == "CN=Zoë 😀"


def test_sanitize_is_idempotent():
    once = safety.sanitize_text("a\ud800b\x00c")
    assert safety.sanitize_text(once) == once == "a\\ud800b\\x00c"


# ------------------------------------------------------------------ safety helpers
@pytest.mark.parametrize("name", ["raw", "der", "pem", "secret", "password", "private_key", "privatekey", "key_material",
                                  "cert_der", "client_secret"])
def test_raw_material_names_are_flagged(name):
    assert safety.is_raw_material_name(name)


@pytest.mark.parametrize("name", ["key_algorithm", "key_size", "key_curve", "sha256", "serial_hex", "subject", "issuer",
                                  "signature_algorithm", "keyword", "modernization"])
def test_legitimate_names_are_not_flagged(name):
    assert not safety.is_raw_material_name(name)


# ------------------------------------------------------------------ the agent's scan summary
def test_summary_facts_from_a_normal_summary():
    facts = fs_record.parse_summary(summary(5, roots=((r"C:\a", "scanned"), (r"C:\b", "overlap"), (r"C:\c", "not_found")),
                                            errors=[dir_error(kind="root")], bundles_truncated=2))
    assert (facts.stop_reason, facts.records, facts.bundles_truncated) == ("completed", 5, 2)
    assert (facts.roots_walked, facts.roots_not_scanned) == (1, 1)            # overlap is neutral, not_found is a gap
    assert facts.errors == ((r"C:\app\private", "root", "PermissionError:WinError 5"),)
    assert "errors" not in facts.stored and facts.stored["roots"][0] == {"root": r"C:\a", "status": "scanned"}


@pytest.mark.parametrize("status, walked, missing", [("scanned", 1, 0), ("partial", 1, 0), ("overlap", 0, 0),
                                                      ("not_reached", 0, 1), ("access_denied", 0, 1), ("not_found", 0, 1),
                                                      ("not_a_directory", 0, 1), ("pending", 0, 1), ("anything", 0, 1)])
def test_root_status_classification(status, walked, missing):
    facts = fs_record.parse_summary(summary(0, roots=((r"C:\a", status),)))
    assert (facts.roots_walked, facts.roots_not_scanned) == (walked, missing)


@pytest.mark.parametrize("bad", [None, [], "x", 5, {"stop_reason": "completed"}, {"roots": "x"},
                                 summary(1, stop_reason="C:\\secret path"), {"roots": [{"root": 5, "status": "scanned"}]},
                                 {"roots": [], "errors": "x"}])
def test_unusable_summaries_return_none(bad):
    assert fs_record.parse_summary(bad) is None


def test_invalid_error_entries_are_dropped_and_counted():
    entries = [dir_error(), dict(path=5, kind="listdir", code="PermissionError:WinError 5"),
               dict(path="C:\\x", kind="weird", code="PermissionError:WinError 5"),
               dict(path="C:\\x", kind="read", code="free text with C:\\secrets"),
               dict(path="C:\\x\n" + ARMOR, kind="read", code="PermissionError:errno 13")]
    facts = fs_record.parse_summary(summary(1, errors=entries, errors_total=5))
    assert len(facts.errors) == 1 and facts.invalid_errors == 4


def test_summary_is_stored_without_unknown_or_hostile_content():
    raw = summary(2, extra_secret="private_key=abc", der="3082...")
    raw["records_by_status"] = {"ok": 2, "C:\\evil\\path": "NaN"}
    facts = fs_record.parse_summary(raw)
    assert set(facts.stored) <= {"stop_reason", "complete", "roots", "elapsed_seconds", "directories_visited",
                                 "entries_visited", "candidate_files", "files_read", "records", "unique_certificates",
                                 "duplicate_observations", "bundles_truncated", "errors_total", "records_by_status", "skipped"}
    assert facts.stored["records_by_status"] == {"ok": 2}
