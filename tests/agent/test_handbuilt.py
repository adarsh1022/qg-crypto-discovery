"""Certificates assembled byte-by-byte, for cases `cryptography` cannot (or will not) produce:
v1 certificates, defective-but-real encodings, unknown algorithms and post-quantum OIDs.
No library and no machine-specific store is involved, so these always run.
"""
import pytest

import oracle
from agent.x509_parse import CertParseError, parse_certificate
from certgen import _enc

RSA_OID = "2a864886f70d010101"
SHA256_RSA_OID = "2a864886f70d01010b"
ML_DSA_65_OID = "608648016503040312"
UNKNOWN_OID = "2a030405"                       # 1.2.3.4.5


def algid(oid_hex: str, params: bytes = b"\x05\x00") -> bytes:
    return _enc(0x30, _enc(6, bytes.fromhex(oid_hex)) + params)


def name(cn: str) -> bytes:
    atv = _enc(0x30, _enc(6, bytes.fromhex("550403")) + _enc(0x0C, cn.encode()))
    return _enc(0x30, _enc(0x31, atv))


def rsa_spki(modulus: bytes) -> bytes:
    key = _enc(0x30, _enc(2, modulus) + _enc(2, b"\x01\x00\x01"))
    return _enc(0x30, algid(RSA_OID) + _enc(3, b"\x00" + key))


def build_v1(spki: bytes, sig_oid: str = SHA256_RSA_OID, sig_params: bytes = b"\x05\x00") -> bytes:
    """A v1 certificate: no version field, no extensions."""
    validity = _enc(0x30, _enc(0x17, b"240101000000Z") + _enc(0x17, b"340101000000Z"))
    tbs = _enc(0x30, _enc(2, b"\x2a") + algid(sig_oid, sig_params) + name("issuer")
               + validity + name("hand-built") + spki)
    return _enc(0x30, tbs + algid(sig_oid, sig_params) + _enc(3, b"\x00" + b"\xaa" * 64))


PADDED_MODULUS = b"\x00" + b"\xc0" + b"\x11" * 63      # correct DER: leading 0x00 because top bit set
UNPADDED_MODULUS = b"\xc0" + b"\x11" * 63              # the "Root Agency" defect: looks negative


def test_v1_certificate_and_oracle_agreement():
    der = build_v1(rsa_spki(PADDED_MODULUS))
    info = parse_certificate(der)
    assert (info.version, info.key_algorithm, info.key_size) == (1, "RSA", 512)
    assert info.subject == "CN=hand-built" and info.issuer == "CN=issuer"
    assert info.serial_hex == "2a" and info.is_ca is None and info.san == ()
    assert info.warnings == ()
    bad, skipped = oracle.compare(info, der)
    assert not bad and not skipped


def test_modulus_missing_leading_zero_is_reported_not_rejected():
    info = parse_certificate(build_v1(rsa_spki(UNPADDED_MODULUS)))
    assert info.key_size == 512
    assert info.warnings == ("rsa_modulus_encoded_as_negative",)


@pytest.mark.parametrize("modulus", [b"\x00", b"\x00\x00\x00"])
def test_zero_modulus_rejected(modulus):
    with pytest.raises(CertParseError):
        parse_certificate(build_v1(rsa_spki(modulus)))


def test_unknown_algorithms_are_named_by_oid_and_flagged():
    unknown_key = _enc(0x30, algid(UNKNOWN_OID) + _enc(3, b"\x00" + b"\x01\x02\x03"))
    info = parse_certificate(build_v1(unknown_key, sig_oid=UNKNOWN_OID))
    assert info.signature_algorithm == info.signature_algorithm_oid == "1.2.3.4.5"
    assert info.key_algorithm == info.key_algorithm_oid == "1.2.3.4.5" and info.key_size is None
    assert set(info.warnings) == {"unknown_signature_algorithm", "unknown_public_key_algorithm"}


def test_post_quantum_oids_are_recognised():
    pq_key = _enc(0x30, algid(ML_DSA_65_OID, b"") + _enc(3, b"\x00" + b"\x5a" * 1952))
    info = parse_certificate(build_v1(pq_key, sig_oid=ML_DSA_65_OID, sig_params=b""))
    assert info.signature_algorithm == "ML-DSA-65"
    assert info.key_algorithm == "ML-DSA-65" and info.key_size is None
    assert info.warnings == ()


def test_unknown_version_is_unsupported_not_malformed():
    validity = _enc(0x30, _enc(0x17, b"240101000000Z") + _enc(0x17, b"340101000000Z"))
    tbs = _enc(0x30, _enc(0xA0, _enc(2, b"\x07")) + _enc(2, b"\x01") + algid(SHA256_RSA_OID)
               + name("i") + validity + name("s") + rsa_spki(PADDED_MODULUS))
    der = _enc(0x30, tbs + algid(SHA256_RSA_OID) + _enc(3, b"\x00" + b"\xaa" * 8))
    with pytest.raises(CertParseError) as e:
        parse_certificate(der)
    assert e.value.code == "unsupported"


def test_signature_algorithm_mismatch_is_flagged():
    validity = _enc(0x30, _enc(0x17, b"240101000000Z") + _enc(0x17, b"340101000000Z"))
    tbs = _enc(0x30, _enc(2, b"\x01") + algid(SHA256_RSA_OID) + name("i") + validity
               + name("s") + rsa_spki(PADDED_MODULUS))
    der = _enc(0x30, tbs + algid("2a864886f70d01010c") + _enc(3, b"\x00" + b"\xaa" * 8))
    info = parse_certificate(der)
    assert info.signature_algorithm == "sha384WithRSAEncryption"       # the outer (authoritative) one
    assert "signature_algorithm_mismatch" in info.warnings


def test_inverted_validity_is_flagged():
    validity = _enc(0x30, _enc(0x17, b"340101000000Z") + _enc(0x17, b"240101000000Z"))
    tbs = _enc(0x30, _enc(2, b"\x01") + algid(SHA256_RSA_OID) + name("i") + validity
               + name("s") + rsa_spki(PADDED_MODULUS))
    info = parse_certificate(_enc(0x30, tbs + algid(SHA256_RSA_OID) + _enc(3, b"\x00" + b"\xaa" * 8)))
    assert "validity_end_before_start" in info.warnings
