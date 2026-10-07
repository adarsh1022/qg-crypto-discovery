"""Hostile / corrupt input: the parser must fail cleanly (CertParseError) and quickly.

Certificate files are untrusted. The only acceptable outcomes for any byte string are
a CertInfo or a CertParseError. Any other exception type is a bug.
"""
import random
import time

import pytest

import certgen
from agent.x509_parse import CertParseError, assess_validity, parse_certificate

BASES = ["key_rsa2048", "key_p256", "key_ed25519", "san_many_200", "name_many_attributes",
         "bc_ca_pathlen3", "sig_rsa_pss_sha256", "name_type_BMPString"]


@pytest.fixture(scope="module")
def bases():
    return {n: certgen.CASES[n][0]() for n in BASES}


def _must_be_clean(data: bytes):
    try:
        parse_certificate(data)
    except CertParseError:
        pass


def test_every_truncation_is_rejected(bases):
    for name, der in bases.items():
        for n in range(len(der)):
            with pytest.raises(CertParseError):
                parse_certificate(der[:n])


def test_random_single_byte_mutations_never_crash(bases):
    rnd = random.Random(20240601)
    start = time.perf_counter()
    count = 0
    for der in bases.values():
        for _ in range(400):
            mutated = bytearray(der)
            mutated[rnd.randrange(len(mutated))] = rnd.randrange(256)
            _must_be_clean(bytes(mutated))
            count += 1
    assert count == 400 * len(bases)
    assert time.perf_counter() - start < 20, "mutation run was suspiciously slow"


def test_random_multi_byte_mutations_never_crash(bases):
    rnd = random.Random(7)
    for der in bases.values():
        for _ in range(150):
            mutated = bytearray(der)
            for _ in range(rnd.randrange(2, 12)):
                mutated[rnd.randrange(len(mutated))] = rnd.randrange(256)
            _must_be_clean(bytes(mutated))


def test_random_garbage_never_crashes():
    rnd = random.Random(99)
    for _ in range(2000):
        _must_be_clean(bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 200))))


@pytest.mark.parametrize("data", [
    b"", b"\x00", b"\x30", b"\x30\x00", b"\x30\x80", b"\x30\x84\xff\xff\xff\xff",
    b"\x30\x03\x30\x03\x30", b"-----BEGIN CERTIFICATE-----", b"\xff" * 64,
    b"\x30\x82\x04\x00" + b"\x30\x00" * 2,             # claims 1 KB, supplies 4 bytes
])
def test_hostile_structures_rejected(data):
    with pytest.raises(CertParseError):
        parse_certificate(data)


def test_deeply_nested_input_does_not_recurse():
    # 200 nested SEQUENCEs. A recursive parser might blow the stack; ours never recurses.
    blob = b"\x05\x00"
    for _ in range(200):
        blob = b"\x30" + bytes([0x82, len(blob) >> 8, len(blob) & 0xFF]) + blob
    with pytest.raises(CertParseError):
        parse_certificate(blob)


def test_size_cap():
    with pytest.raises(CertParseError) as e:
        parse_certificate(b"\x30" * 100, max_size=50)
    assert e.value.code == "too_large"


def test_wrong_error_code_for_garbage():
    with pytest.raises(CertParseError) as e:
        parse_certificate(b"not a certificate at all")
    assert e.value.code == "malformed"


def test_trailing_data_is_reported_not_hashed(bases):
    import hashlib
    der = bases["key_p256"]
    info = parse_certificate(der + b"TRAILING-GARBAGE")
    assert info.trailing_bytes == len(b"TRAILING-GARBAGE")
    assert "trailing_data_after_certificate" in info.warnings
    assert info.sha256 == hashlib.sha256(der).hexdigest()       # identity ignores the junk
    assert info.der_length == len(der)


def test_bytes_like_input_accepted(bases):
    der = bases["key_p256"]
    assert parse_certificate(bytearray(der)).sha256 == parse_certificate(memoryview(der)).sha256


# ---------------------------------------------------------------- assess_validity
import datetime as dt

UTC = dt.timezone.utc
NB, NA = dt.datetime(2024, 1, 1, tzinfo=UTC), dt.datetime(2024, 12, 31, tzinfo=UTC)


def _v(now, **kw):
    return assess_validity(NB, NA, now, **kw)


def test_validity_valid():
    v = _v(dt.datetime(2024, 6, 1, tzinfo=UTC))
    assert (v.status, v.not_yet_valid) == ("valid", False) and v.days_to_expiry == 213


def test_validity_expiring_boundary_is_inclusive():
    now = NA - dt.timedelta(days=30)
    assert _v(now).status == "expiring" and _v(now).days_to_expiry == 30
    assert _v(NA - dt.timedelta(days=31)).status == "valid"
    assert _v(NA - dt.timedelta(days=10), expiring_days=5).status == "valid"
    assert _v(NA - dt.timedelta(days=4), expiring_days=5).status == "expiring"


def test_validity_expiry_instant():
    assert _v(NA).status == "expiring" and _v(NA).days_to_expiry == 0        # on the last second
    just_after = _v(NA + dt.timedelta(seconds=1))
    assert just_after.status == "expired" and just_after.days_to_expiry == -1  # floor, not truncate


def test_validity_expired_days_are_negative():
    v = _v(NA + dt.timedelta(days=10))
    assert v.status == "expired" and v.days_to_expiry == -10


def test_validity_not_yet_valid_is_separate_flag():
    v = _v(NB - dt.timedelta(days=5))
    assert v.not_yet_valid is True and v.status == "valid"


def test_validity_year_9999():
    v = assess_validity(NB, dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC), NA)
    assert v.status == "valid" and v.days_to_expiry > 2_000_000


def test_validity_requires_aware_datetimes():
    with pytest.raises(ValueError):
        assess_validity(NB, NA, dt.datetime(2024, 6, 1))
