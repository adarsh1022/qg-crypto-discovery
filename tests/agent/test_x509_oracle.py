"""Our stdlib parser vs `cryptography` on generated certificates.

Two independent checks per case:
  1. full agreement with the oracle on every field it can judge;
  2. the handful of facts in CASES[...][1], asserted directly so a bug shared by
     both views (or an oracle quirk) cannot hide.
"""
import pytest

import certgen
import oracle
from agent.x509_parse import parse_certificate


def _san(info):
    return [(s.type, s.value) for s in info.san]


@pytest.mark.parametrize("case_name", list(certgen.CASES))
def test_matches_oracle_and_expectations(case_name):
    builder, expected = certgen.CASES[case_name]
    der = builder()
    info = parse_certificate(der)

    mismatches, skipped = oracle.compare(info, der)
    assert not mismatches, "\n".join(mismatches)
    assert not skipped, f"oracle could not judge: {skipped}"
    assert not info.warnings, f"generated certificates must parse cleanly: {info.warnings}"
    assert info.trailing_bytes == 0 and info.der_length == len(der)

    for field, want in expected.items():
        got = _san(info) if field == "san" else getattr(info, field)
        assert got == want, f"{field}: got {got!r}, want {want!r}"


def test_san_and_subject_survive_to_dict():
    builder, _ = certgen.CASES["san_ip"]
    d = parse_certificate(builder()).to_dict()
    assert d["san"] == [{"type": "ip", "value": "192.0.2.1"}, {"type": "ip", "value": "2001:db8::1"}]
    assert d["not_before"] == "2024-01-01T00:00:00Z" and d["not_after"] == "2034-01-01T00:00:00Z"
    import json
    json.dumps(d)       # must be JSON-serialisable as is


def test_same_certificate_same_fingerprint_across_calls():
    builder, _ = certgen.CASES["key_p256"]
    der = builder()
    assert parse_certificate(der).sha256 == parse_certificate(bytes(der)).sha256
