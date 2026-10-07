"""parse_cert_bytes / sniff_format: formats, bundles, statuses, oracle agreement, robustness."""
import builtins
import hashlib
import io
import random
import ssl
import sys
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.serialization import pkcs12

import certgen
import pemgen
from agent.cert_file import parse_cert_bytes, sniff_format

P256 = pemgen.der_of("key_p256")
RSA = pemgen.der_of("key_rsa2048")
ED = pemgen.der_of("key_ed25519")
FP = {d: hashlib.sha256(d).hexdigest() for d in (P256, RSA, ED)}


def fps(result):
    return [e.cert.sha256 if e.cert else None for e in result.entries]


# ---------------------------------------------------------------- happy paths
def test_single_pem():
    r = parse_cert_bytes(pemgen.pem_encode(P256))
    assert (r.format, r.file_status, r.detail, r.truncated) == ("pem", "ok", None, False)
    assert fps(r) == [FP[P256]] and r.entries[0].index == 0 and r.total_certificates == 1


def test_single_der():
    r = parse_cert_bytes(P256)
    assert (r.format, r.file_status) == ("der", "ok")
    assert fps(r) == [FP[P256]] and r.entries[0].index == 0


def test_same_certificate_same_fingerprint_in_pem_and_der():
    assert fps(parse_cert_bytes(P256)) == fps(parse_cert_bytes(pemgen.pem_encode(P256)))


def test_bundle_order_and_indexes():
    data = pemgen.pem_encode(P256) + b"# comment\n" + pemgen.pem_encode(RSA) + pemgen.pem_encode(ED)
    r = parse_cert_bytes(data)
    assert r.file_status == "ok" and r.total_certificates == 3
    assert fps(r) == [FP[P256], FP[RSA], FP[ED]]
    assert [e.index for e in r.entries] == [0, 1, 2]


def test_bundle_of_150_certificates():
    ders = [P256, RSA, ED] * 50
    data = b"".join(pemgen.pem_encode(d, width=64 if i % 2 else 76) for i, d in enumerate(ders))
    r = parse_cert_bytes(data)
    assert r.file_status == "ok" and r.total_certificates == 150 and not r.truncated
    assert [e.index for e in r.entries] == list(range(150))
    assert fps(r) == [FP[d] for d in ders]


def test_trusted_certificate_aux_data_is_flagged_not_fatal():
    der_with_aux = P256 + b"\x30\x05\x0c\x03aux"           # OpenSSL "trust" trailer
    r = parse_cert_bytes(pemgen.pem_encode(der_with_aux, label=b"TRUSTED CERTIFICATE"))
    assert r.file_status == "ok"
    assert fps(r) == [FP[P256]]                              # identity ignores the trailer
    assert "trailing_data_after_certificate" in r.entries[0].cert.warnings


def test_utf8_bom_pem():
    assert fps(parse_cert_bytes(b"\xef\xbb\xbf" + pemgen.pem_encode(P256))) == [FP[P256]]


def test_other_blocks_do_not_change_the_certificate_result():
    csr = pemgen.pem_encode(b"\x30\x03\x02\x01\x00", label=b"CERTIFICATE REQUEST")
    r = parse_cert_bytes(csr + pemgen.pem_encode(P256) + csr)
    assert r.file_status == "ok" and fps(r) == [FP[P256]] and r.entries[0].index == 0


# ---------------------------------------------------------------- statuses
def test_status_partial_and_indexes_survive_a_bad_neighbour():
    bad = b"-----BEGIN CERTIFICATE-----\nAAA*AAAA\n-----END CERTIFICATE-----\n"
    r = parse_cert_bytes(pemgen.pem_encode(P256) + bad + pemgen.pem_encode(RSA))
    assert r.file_status == "partial" and r.total_certificates == 3
    assert [e.parse_status for e in r.entries] == ["ok", "malformed", "ok"]
    assert r.entries[1].detail == "pem_bad_base64" and r.entries[1].cert is None
    assert fps(r) == [FP[P256], None, FP[RSA]]


@pytest.mark.parametrize("data,detail", [
    (b"-----BEGIN CERTIFICATE-----\nAAAA\n", "pem_unterminated_block"),
    (b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END X509 CERTIFICATE-----\n", "pem_label_mismatch"),
    (b"-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n", "pem_empty_body"),
    (b"-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nAAAA\n-----END CERTIFICATE-----\n",
     "pem_headers_unsupported"),
])
def test_pem_level_failures_are_malformed_files(data, detail):
    r = parse_cert_bytes(data)
    assert (r.format, r.file_status) == ("pem", "malformed")
    assert r.entries[0].detail == detail


def test_valid_base64_that_is_not_a_certificate():
    r = parse_cert_bytes(pemgen.pem_encode(b"hello, this is not DER"))
    assert r.file_status == "malformed"
    assert r.entries[0].detail.startswith("x509_malformed: ")


def test_truncated_der_inside_pem_is_malformed():
    r = parse_cert_bytes(pemgen.pem_encode(P256[:-10]))
    assert r.file_status == "malformed" and r.entries[0].detail.startswith("x509_malformed")


def test_nested_begin_gives_partial():
    data = b"-----BEGIN CERTIFICATE-----\nAAAA\n" + pemgen.pem_encode(P256)
    r = parse_cert_bytes(data)
    assert r.file_status == "partial"
    assert [e.parse_status for e in r.entries] == ["malformed", "ok"]


def test_unsupported_certificate_version_is_unsupported():
    from test_handbuilt import SHA256_RSA_OID, PADDED_MODULUS, algid, name, rsa_spki
    from certgen import _enc
    validity = _enc(0x30, _enc(0x17, b"240101000000Z") + _enc(0x17, b"340101000000Z"))
    tbs = _enc(0x30, _enc(0xA0, _enc(2, b"\x07")) + _enc(2, b"\x01") + algid(SHA256_RSA_OID)
               + name("i") + validity + name("s") + rsa_spki(PADDED_MODULUS))
    der = _enc(0x30, tbs + algid(SHA256_RSA_OID) + _enc(3, b"\x00" + b"\xaa" * 8))
    r = parse_cert_bytes(pemgen.pem_encode(der))
    assert r.file_status == "unsupported" and r.entries[0].parse_status == "unsupported"


def test_no_certificate_cases():
    for data in (pemgen.pem_encode(b"x", label=b"PRIVATE KEY"),
                 pemgen.pem_encode(b"x", label=b"CERTIFICATE REQUEST"),
                 pemgen.pem_encode(b"x", label=b"X509 CRL") + b"\nmore text\n"):
        r = parse_cert_bytes(data)
        assert (r.format, r.file_status, r.entries) == ("pem", "no_certificate", ())
    r = parse_cert_bytes(b"")
    assert (r.file_status, r.detail) == ("no_certificate", "empty_file")


def test_too_large_file():
    r = parse_cert_bytes(pemgen.pem_encode(P256), max_size=100)
    assert (r.file_status, r.detail) == ("too_large", "file_too_large")


def test_utf16_is_unsupported_and_not_decoded():
    text = pemgen.pem_encode(P256).decode()
    for enc in ("utf-16", "utf-16-be"):
        data = text.encode("utf-16") if enc == "utf-16" else b"\xfe\xff" + text.encode("utf-16-be")
        r = parse_cert_bytes(data)
        assert (r.file_status, r.detail, r.entries) == ("unsupported", "utf16_text_unsupported", ())


def test_every_documented_file_status_is_reachable():
    seen = {parse_cert_bytes(d).file_status for d in (
        pemgen.pem_encode(P256),                                                     # ok
        pemgen.pem_encode(P256) + b"-----BEGIN CERTIFICATE-----\nAAAA\n",           # partial
        b"-----BEGIN CERTIFICATE-----\nAAAA\n",                                     # malformed
        b"", b"\xff\xfeAAAA")}                                                       # no_certificate, unsupported
    seen.add(parse_cert_bytes(P256, max_size=10).file_status)                        # too_large
    assert seen == {"ok", "partial", "malformed", "no_certificate", "unsupported", "too_large"}


# ---------------------------------------------------------------- limits
def test_max_certs_truncation():
    data = b"".join(pemgen.pem_encode(P256) for _ in range(5))
    r = parse_cert_bytes(data, max_certs=3)
    assert len(r.entries) == 3 and r.truncated and r.detail == "bundle_truncated"
    r = parse_cert_bytes(data, max_certs=5)
    assert len(r.entries) == 5 and not r.truncated and r.detail is None


def test_default_max_certs_is_1000():
    data = pemgen.pem_encode(P256) * 1005
    r = parse_cert_bytes(data)
    assert len(r.entries) == 1000 and r.truncated


# ---------------------------------------------------------------- sniffing
def _pfx(password):
    cert = x509.load_der_x509_certificate(RSA)
    enc = ser.BestAvailableEncryption(password) if password else ser.NoEncryption()
    return pkcs12.serialize_key_and_certificates(b"fixture", certgen.key("rsa2048"), cert, None, enc)


def test_pkcs12_is_sniffed_and_reported_unsupported():
    for password in (None, b"secret"):
        data = _pfx(password)
        assert sniff_format(data) == "pkcs12"
        r = parse_cert_bytes(data)
        assert (r.format, r.file_status, r.detail, r.entries) == (
            "pkcs12", "unsupported", "pkcs12_not_handled_yet", ())


def test_der_that_is_not_a_certificate():
    key_der = certgen.key("p256").private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    r = parse_cert_bytes(key_der)
    assert (r.format, r.file_status, r.detail, r.entries) == ("der", "no_certificate", "der_not_a_certificate", ())


def test_unrecognised_content():
    for data in (b"hello world", bytes(range(256)), b"\x30\x03\x01\x02", b"0" * 50, b"\x00" * 10):
        r = parse_cert_bytes(data)
        assert (r.format, r.file_status, r.detail) == ("unknown", "malformed", "unrecognized_content")


def test_der_wins_over_pem_text_embedded_in_a_name():
    nasty = "x\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    der = certgen.make(certgen.name(nasty))
    assert b"-----BEGIN CERTIFICATE-----" in der
    r = parse_cert_bytes(der)
    assert (r.format, r.file_status) == ("der", "ok") and r.entries[0].cert.subject.startswith("CN=x")


@pytest.mark.parametrize("data_kind,hint,mismatch", [
    ("pem", "a.pem", False), ("pem", "a.crt", False), ("pem", "a.CER", False), ("pem", "a.der", True),
    ("pem", "a.pfx", True), ("der", "a.der", False), ("der", "a.cer", False), ("der", "a.pem", True),
    ("der", "C:\\x\\a.p12", True), ("pem", "a.txt", False), ("pem", None, False), ("pem", "noext", False),
])
def test_extension_mismatch(data_kind, hint, mismatch):
    data = P256 if data_kind == "der" else pemgen.pem_encode(P256)
    assert parse_cert_bytes(data, filename_hint=hint).extension_mismatch is mismatch


def test_extension_mismatch_for_misnamed_pfx():
    assert parse_cert_bytes(_pfx(None), filename_hint="cert.crt").extension_mismatch is True
    assert parse_cert_bytes(_pfx(None), filename_hint="cert.pfx").extension_mismatch is False


def test_non_bytes_is_a_programming_error():
    with pytest.raises(TypeError):
        parse_cert_bytes("-----BEGIN CERTIFICATE-----")


def test_bytes_like_inputs():
    pem = pemgen.pem_encode(P256)
    assert fps(parse_cert_bytes(bytearray(pem))) == fps(parse_cert_bytes(memoryview(pem))) == [FP[P256]]


def test_no_file_access(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("parse_cert_bytes must not touch the filesystem")
    monkeypatch.setattr(builtins, "open", boom)
    monkeypatch.setattr(io, "open", boom)
    assert parse_cert_bytes(pemgen.pem_encode(P256)).file_status == "ok"
    assert parse_cert_bytes(P256).file_status == "ok"
    assert parse_cert_bytes(b"junk").file_status == "malformed"


# ---------------------------------------------------------------- oracle agreement on bundles
def test_generated_bundle_matches_cryptography_oracle():
    ders = [certgen.CASES[n][0]() for n in ("key_p256", "key_rsa2048", "key_ed25519", "san_many_200",
                                            "name_many_attributes", "sig_rsa_pss_sha256")]
    data = b"".join(pemgen.pem_encode(d, width=64 if i % 2 else 76) for i, d in enumerate(ders))
    ours = parse_cert_bytes(data)
    theirs = x509.load_pem_x509_certificates(data)
    assert ours.file_status == "ok"
    assert fps(ours) == [c.fingerprint(hashes.SHA256()).hex() for c in theirs]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows certificate store only")
def test_real_world_bundle_from_windows_store():
    ders = {}
    for store in ("ROOT", "CA"):
        for der, enc, _ in ssl.enum_certificates(store):
            if enc == "x509_asn":
                ders.setdefault(hashlib.sha256(der).hexdigest(), bytes(der))
    ordered = list(ders.values())
    bundle = b"".join(pemgen.pem_encode(d) for d in ordered)
    start = time.perf_counter()
    ours = parse_cert_bytes(bundle)
    elapsed = time.perf_counter() - start
    assert ours.file_status == "ok" and len(ours.entries) == len(ordered) >= 100
    assert fps(ours) == [hashlib.sha256(d).hexdigest() for d in ordered]
    assert not ours.truncated
    assert elapsed < 5, f"{len(ordered)} certificates took {elapsed:.2f}s"
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        assert len(x509.load_pem_x509_certificates(bundle)) == len(ordered)


# ---------------------------------------------------------------- robustness
ALLOWED_FILE_STATUS = {"ok", "partial", "malformed", "no_certificate", "unsupported", "too_large"}


def _check_sane(result):
    assert result.file_status in ALLOWED_FILE_STATUS
    assert result.detail != "internal_error"
    for e in result.entries:
        assert e.detail != "internal_error"
        assert (e.cert is not None) == (e.parse_status == "ok")


def test_every_truncation_of_a_bundle_is_handled():
    data = pemgen.pem_encode(P256) + b"text\n" + pemgen.pem_encode(RSA)
    for n in range(len(data) + 1):
        _check_sane(parse_cert_bytes(data[:n]))


def test_mutation_fuzz_on_pem_bundle():
    base = (b"preamble: x\n" + pemgen.pem_encode(P256) + pemgen.pem_encode(RSA, eol=b"\r\n")
            + pemgen.pem_encode(b"k", label=b"PRIVATE KEY") + pemgen.pem_encode(ED, width=76))
    rnd = random.Random(1234)
    start = time.perf_counter()
    for _ in range(2000):
        mutated = bytearray(base)
        for _ in range(rnd.randrange(1, 8)):
            mutated[rnd.randrange(len(mutated))] = rnd.randrange(256)
        _check_sane(parse_cert_bytes(bytes(mutated)))
    assert time.perf_counter() - start < 30


def test_line_deletion_and_duplication_fuzz():
    lines = (pemgen.pem_encode(P256) + pemgen.pem_encode(RSA)).splitlines(keepends=True)
    rnd = random.Random(5)
    for _ in range(500):
        picked = [ln for ln in lines if rnd.random() > 0.1]
        picked += [rnd.choice(lines) for _ in range(rnd.randrange(3))]
        rnd.shuffle(picked)
        _check_sane(parse_cert_bytes(b"".join(picked)))


def test_random_binary_and_pem_flavoured_garbage():
    rnd = random.Random(77)
    prefixes = [b"", b"-----BEGIN CERTIFICATE-----\n", b"\x30\x82", b"\xef\xbb\xbf", b"\xff\xfe"]
    for _ in range(3000):
        blob = rnd.choice(prefixes) + bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 300)))
        _check_sane(parse_cert_bytes(blob))


def test_pathological_inputs_finish_quickly():
    start = time.perf_counter()
    for data in (b"-----BEGIN CERTIFICATE-----\n" * 100_000,
                 b"-----BEGIN FOO-----\n" * 100_000,
                 b"A" * 5_000_000,
                 pemgen.pem_encode(b"\x00" * 600_000)):
        _check_sane(parse_cert_bytes(data))
    assert time.perf_counter() - start < 15
