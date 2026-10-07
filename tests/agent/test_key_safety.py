"""Private-key safety for PEM/DER/PFX handling (Phase 1b).

The guarantee under test: key material never reaches an output, an exception message, a log
line or a decoder, and the presence of key blocks cannot change the result at all.

Method: key fixtures carry *canaries* - every 32-character window of the key's base64 body
and of the hex of its DER. If any canary appears in any output channel, the test fails.
A negative control proves the detector actually fires.
"""
import base64
import binascii
import dataclasses
import json
import logging
import random
import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.serialization import pkcs12

import certgen
import pemgen
from agent import cert_file
from agent.cert_file import CertEntry, FileParse, parse_cert_bytes
from agent.x509_parse import CertInfo

CERT = pemgen.pem_encode(pemgen.der_of("sig_rsa_sha256"))
KEYS = pemgen.private_key_pems()
SAFE_DETAIL = re.compile(r"^[A-Za-z0-9 _.,:;()/#'=<>+\-\[\]]{0,200}$")


def layouts(key: bytes, cert: bytes = CERT) -> dict[str, bytes]:
    half = key[: len(key) // 2]
    return {
        "cert_key": cert + key,
        "key_cert": key + cert,
        "key_cert_key": key + cert + key,
        "truncated_key_then_cert": half + b"\n" + cert,
        "cert_then_truncated_key": cert + half,
        "garbage_in_key_then_cert": key[:80] + b"\x00\xffGARBAGE\x01\n" + key[80:] + cert,
        "mismatched_end_then_cert": key.replace(b"-----END ", b"-----END X ", 1) + cert,
        "inside_openssl_preamble": (b"Bag Attributes\n    localKeyID: 01 02\nKey Attributes: <No Attributes>\n"
                                    + key + b"Bag Attributes\n    friendlyName: x\nsubject=/CN=x\n" + cert),
    }


def haystack(result: FileParse) -> str:
    return json.dumps(result.to_dict()) + repr(result) + str(result.to_dict())


def all_details(result: FileParse):
    yield result.detail
    for e in result.entries:
        yield e.detail


KEY_NAMES = list(KEYS)


# ---------------------------------------------------------------- the detector must be able to fire
def test_negative_control_detector_fires():
    for name, key in KEYS.items():
        canaries = pemgen.canary_set(key)
        body = pemgen.key_body_text(key)
        assert len(body) >= 36 and len(canaries) > 10
        mid = len(body) // 4
        assert pemgen.leaked("prefix " + body[mid:mid + 36] + " suffix", canaries), name   # partial leak caught
        assert pemgen.leaked(json.dumps({"detail": body}), canaries), name            # whole leak caught
        assert not pemgen.leaked(json.dumps(parse_cert_bytes(CERT).to_dict()), canaries), name


# ---------------------------------------------------------------- 1. canary scan of every output
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_no_key_text_in_output(key_name):
    key = KEYS[key_name]
    canaries = pemgen.canary_set(key)
    cases = {"key_only": key, **layouts(key)}
    for layout, data in cases.items():
        result = parse_cert_bytes(data)
        text = haystack(result)
        assert not pemgen.leaked(text, canaries), f"{key_name}/{layout} leaked key text"
        for marker in ("PRIVATE", "ENCRYPTED", "BEGIN ", "-----", "DEK-Info", "Proc-Type", "OPENSSH"):
            assert marker not in text, f"{key_name}/{layout}: marker {marker!r} in output"


# ---------------------------------------------------------------- 2. key blocks cannot change the result
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_adding_or_damaging_key_blocks_never_changes_output(key_name):
    baseline = parse_cert_bytes(CERT).to_dict()
    for layout, data in layouts(KEYS[key_name]).items():
        assert parse_cert_bytes(data).to_dict() == baseline, f"{key_name}/{layout}"


@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_key_between_two_certificates(key_name):
    key = KEYS[key_name]
    other = pemgen.pem_encode(pemgen.der_of("key_p256"))
    baseline = parse_cert_bytes(CERT + other).to_dict()
    canaries = pemgen.canary_set(key)
    truncated_key = key[: len(key) // 2] + b"\n"
    for data in (CERT + key + other, CERT + truncated_key + other):
        result = parse_cert_bytes(data)
        assert result.to_dict() == baseline
        assert [e.index for e in result.entries] == [0, 1]
        assert not pemgen.leaked(haystack(result), canaries)


@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_key_only_file_is_indistinguishable_from_other_certificate_free_files(key_name):
    csr_only = parse_cert_bytes(pemgen.pem_encode(b"\x30\x00", label=b"CERTIFICATE REQUEST")).to_dict()
    crl_only = parse_cert_bytes(pemgen.pem_encode(b"\x30\x00", label=b"X509 CRL")).to_dict()
    key_only = parse_cert_bytes(KEYS[key_name]).to_dict()
    assert key_only == csr_only == crl_only
    assert key_only["file_status"] == "no_certificate" and key_only["entries"] == []


def test_der_key_and_pfx_results_carry_no_content_dependent_data():
    k1 = certgen.key("p256").private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    k2 = certgen.key("rsa2048").private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    other_der = b"\x30\x06\x02\x01\x00\x02\x01\x01"                       # some non-certificate DER
    results = [parse_cert_bytes(d).to_dict() for d in (k1, k2, other_der)]
    assert results[0] == results[1] == results[2]

    cert = x509.load_der_x509_certificate(pemgen.der_of("key_rsa2048"))
    pfx = [pkcs12.serialize_key_and_certificates(b"n", certgen.key("rsa2048"), cert, None, enc)
           for enc in (ser.NoEncryption(), ser.BestAvailableEncryption(b"pw"))]
    assert parse_cert_bytes(pfx[0]).to_dict() == parse_cert_bytes(pfx[1]).to_dict()

    for blob in (k1, k2, *pfx):
        for canary_text in (blob.hex(), base64.b64encode(blob).decode()):
            canaries = pemgen.canary_windows(canary_text, 32, 1)
            assert not pemgen.leaked(haystack(parse_cert_bytes(blob)), canaries)


# ---------------------------------------------------------------- 3. key bodies are never even decoded
@pytest.fixture
def decode_spy(monkeypatch):
    seen: list[bytes] = []

    def wrap(module, attr):
        original = getattr(module, attr)

        def spy(*args, **kwargs):
            for a in args:
                if isinstance(a, (bytes, bytearray)):
                    seen.append(bytes(a))
                elif isinstance(a, str):
                    seen.append(a.encode("latin-1", "replace"))
            return original(*args, **kwargs)
        monkeypatch.setattr(module, attr, spy)

    for module, attr in [(binascii, "a2b_base64"), (base64, "b64decode"), (base64, "decodebytes"),
                         (base64, "standard_b64decode"), (cert_file, "decode_block"),
                         (cert_file, "parse_certificate")]:
        wrap(module, attr)
    return seen


@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_key_bodies_never_reach_a_decoder_or_the_certificate_parser(decode_spy, key_name):
    key = KEYS[key_name]
    body = pemgen.key_body_text(key)
    key_der = base64.b64decode(body)
    canaries_b64 = pemgen.canary_windows(body, 32, 1)
    cert_b64 = pemgen.key_body_text(CERT)

    for layout, data in layouts(key).items():
        decode_spy.clear()
        parse_cert_bytes(data)
        assert decode_spy, f"{layout}: spy saw nothing, so this test would be vacuous"
        blob = b"\n".join(decode_spy)
        assert any(cert_b64[:40].encode() in s for s in decode_spy), f"{layout}: certificate not decoded?"
        assert not pemgen.leaked(blob.decode("latin-1"), canaries_b64), f"{key_name}/{layout}"
        for i in range(0, len(key_der) - 16 + 1):                      # raw DER windows of the key
            assert key_der[i:i + 16] not in blob, f"{key_name}/{layout}: raw key bytes reached a decoder"


# ---------------------------------------------------------------- 4. no side channels
def test_no_stdout_stderr_or_log_output(capsys, caplog):
    caplog.set_level(logging.DEBUG)
    for key in KEYS.values():
        for data in (key, *layouts(key).values()):
            parse_cert_bytes(data)
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    assert caplog.text == ""


# ---------------------------------------------------------------- 5. structural guarantees
def _walk(value):
    yield value
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(k)
            yield from _walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v)


@pytest.mark.parametrize("data", [CERT, pemgen.der_of("key_p256"), KEYS["pkcs8_rsa"] + CERT, b"junk", b""])
def test_output_contains_only_plain_json_types(data):
    for item in _walk(parse_cert_bytes(data).to_dict()):
        assert item is None or isinstance(item, (str, int, bool, list, dict)), type(item)
        assert not isinstance(item, (bytes, bytearray, memoryview))


def test_result_types_have_no_bytes_valued_fields():
    for cls in (FileParse, CertEntry, CertInfo):
        for f in dataclasses.fields(cls):
            assert "bytes" not in str(f.type), f"{cls.__name__}.{f.name}: {f.type}"


def test_detail_strings_are_fixed_safe_text():
    samples = [CERT, b"-----BEGIN CERTIFICATE-----\nAAAA\n", b"-----BEGIN CERTIFICATE-----\nA*A\n-----END CERTIFICATE-----\n",
               pemgen.pem_encode(b"not der"), b"\xff\xfe", b"", b"junk", pemgen.pem_encode(pemgen.der_of("key_p256")[:-5])]
    for key in KEYS.values():
        samples += list(layouts(key).values())
    for data in samples:
        for detail in all_details(parse_cert_bytes(data)):
            assert detail is None or SAFE_DETAIL.match(detail), detail


# ---------------------------------------------------------------- 6. fuzzing with canaries
@pytest.mark.parametrize("key_name", ["pkcs8_rsa", "encrypted_traditional_rsa", "openssh_ed25519", "traditional_ec"])
def test_mutated_key_bearing_files_never_leak(key_name):
    key = KEYS[key_name]
    canaries = pemgen.canary_set(key, n=24, step=2)
    base = key + CERT + key
    rnd = random.Random(f"fuzz-{key_name}")
    for _ in range(400):
        mutated = bytearray(base)
        for _ in range(rnd.randrange(1, 10)):
            mutated[rnd.randrange(len(mutated))] = rnd.randrange(256)
        if rnd.random() < 0.3:                                       # also drop a random chunk
            a = rnd.randrange(len(mutated))
            del mutated[a:a + rnd.randrange(1, 200)]
        result = parse_cert_bytes(bytes(mutated))
        assert result.detail != "internal_error"
        assert not pemgen.leaked(haystack(result), canaries)
        for detail in all_details(result):
            assert detail is None or SAFE_DETAIL.match(detail), detail


def test_every_truncation_of_a_key_bearing_file_never_leaks():
    key = KEYS["pkcs8_rsa"]
    canaries = pemgen.canary_set(key, n=24, step=1)
    data = key + CERT + key
    for n in range(0, len(data) + 1, 3):
        assert not pemgen.leaked(haystack(parse_cert_bytes(data[:n])), canaries)


# ---------------------------------------------------------------- 7. realistic case: key + ITS OWN certificate
# A combined "key + cert" PEM usually holds a matching pair. The certificate legitimately contains
# the key's PUBLIC half, so these tests use canaries built from PRIVATE components only
# (RSA d/p/q/dp/dq/qinv, EC scalar, Ed25519 seed) in raw form, and still require the outputs to be
# identical with and without the key blocks.
PAIRS = [("rsa2048", "sig_rsa_sha256"), ("p256", "key_p256"), ("ed25519", "key_ed25519")]
FORMATS = {"pkcs8": (ser.PrivateFormat.PKCS8,), "openssh": (ser.PrivateFormat.OpenSSH,),
           "traditional": (ser.PrivateFormat.TraditionalOpenSSL,)}


def _pair_key_pem(kind, fmt_name):
    return certgen.key(kind).private_bytes(ser.Encoding.PEM, FORMATS[fmt_name][0], ser.NoEncryption())


def _raw_windows(components, size=16):
    out = set()
    for c in components:
        out |= {c[i:i + size] for i in range(0, max(len(c) - size + 1, 1))}
    return out


PAIR_CASES = [(k, c, f) for k, c in PAIRS for f in FORMATS
              if not (k == "ed25519" and f == "traditional")]      # that format does not exist for Ed25519


@pytest.mark.parametrize("kind,cert_case,fmt_name", PAIR_CASES)
def test_matching_key_and_certificate_pair(decode_spy, kind, cert_case, fmt_name):
    key_pem = _pair_key_pem(kind, fmt_name)
    cert_der = pemgen.der_of(cert_case)
    cert_pem = pemgen.pem_encode(cert_der)
    baseline = parse_cert_bytes(cert_pem).to_dict()
    private_windows = _raw_windows(pemgen.private_components(certgen.key(kind)))
    full_key_canaries = pemgen.canary_set(key_pem)

    for layout in ("cert_key", "key_cert", "key_cert_key"):
        data = layouts(key_pem, cert_pem)[layout]
        decode_spy.clear()
        result = parse_cert_bytes(data)
        # (1) identical to the certificate-only result
        assert result.to_dict() == baseline, f"{kind}/{fmt_name}/{layout}"
        # (2) nothing from the key in the output (the output never contains the public modulus either)
        assert not pemgen.leaked(haystack(result), full_key_canaries)
        # (3) no private component reached a decoder or the certificate parser
        blob = b"\n".join(decode_spy)
        assert any(cert_der in s for s in decode_spy), "spy must have seen the certificate (control)"
        assert all(w not in blob for w in private_windows), f"{kind}/{fmt_name}/{layout}: private bytes decoded"
