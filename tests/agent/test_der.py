"""Unit tests for the DER reader, using hand-built byte vectors."""
import pytest

from agent import der
from agent.der import DerError, Tlv, children, read_tlv


# ---------------------------------------------------------------- read_tlv
def test_short_form_length():
    t = read_tlv(b"\x04\x03abc")
    assert (t.tag, t.value, t.raw) == (der.OCTET_STRING, b"abc", b"\x04\x03abc")


@pytest.mark.parametrize("length_bytes,length", [(b"\x81\x80", 128), (b"\x82\x01\x00", 256),
                                                 (b"\x84\x00\x00\x01\x00", 256)])
def test_long_form_length(length_bytes, length):
    t = read_tlv(b"\x04" + length_bytes + b"x" * length)
    assert len(t.value) == length


@pytest.mark.parametrize("data,why", [
    (b"", "empty"), (b"\x04", "tag only"), (b"\x30\x80\x00\x00", "indefinite length"),
    (b"\x04\x05abc", "length beyond buffer"), (b"\x04\x82\x01", "truncated length bytes"),
    (b"\x04\x85\x00\x00\x00\x00\x01x", "length field > 4 octets"),
    (b"\x1f\x81\x00\x00", "high tag number form"),
])
def test_rejects_bad_headers(data, why):
    with pytest.raises(DerError):
        read_tlv(data)


def test_respects_explicit_end():
    buf = b"\x04\x03abcdef"
    assert read_tlv(buf, 0, 5).value == b"abc"
    with pytest.raises(DerError):
        read_tlv(buf, 0, 4)          # element would run past the allowed end


def test_children_must_consume_content_exactly():
    seq = read_tlv(b"\x30\x06\x02\x01\x05\x02\x01\x07")
    assert [c.value for c in children(seq)] == [b"\x05", b"\x07"]
    with pytest.raises(DerError):
        children(read_tlv(b"\x30\x04\x02\x01\x05\x02"))      # dangling half element


def test_children_cannot_read_outside_parent():
    outer = b"\x30\x03\x02\x05\x01\x02\x03\x04\x05"           # inner claims 5, parent has 1
    with pytest.raises(DerError):
        children(read_tlv(outer))


# ---------------------------------------------------------------- OID
def _enc_oid(dotted: str) -> bytes:
    a = [int(x) for x in dotted.split(".")]
    subs = [a[0] * 40 + a[1]] + a[2:]
    out = b""
    for s in subs:
        chunk = [s & 0x7F]
        s >>= 7
        while s:
            chunk.append(0x80 | (s & 0x7F))
            s >>= 7
        out += bytes(reversed(chunk))
    return out


@pytest.mark.parametrize("dotted,raw", [
    ("1.2.840.113549.1.1.11", bytes.fromhex("2a864886f70d01010b")),
    ("2.5.4.3", bytes.fromhex("550403")),
    ("2.999.3", bytes.fromhex("883703")),
    ("1.3.101.112", bytes.fromhex("2b6570")),
])
def test_oid_known_vectors(dotted, raw):
    assert der.decode_oid(raw) == dotted


@pytest.mark.parametrize("dotted", ["0.9.2342.19200300.100.1.25", "1.3.6.1.4.1.311.60.2.1.3",
                                    "2.16.840.1.101.3.4.3.18", "2.100.3", "1.2.3.4.5.6.7.8.9.10.11"])
def test_oid_round_trip(dotted):
    assert der.decode_oid(_enc_oid(dotted)) == dotted


@pytest.mark.parametrize("raw", [b"", b"\x2a\x86", b"\x80" * 200])
def test_oid_rejects_bad(raw):
    with pytest.raises(DerError):
        der.decode_oid(raw)


# ---------------------------------------------------------------- INTEGER / BOOLEAN / BIT STRING
@pytest.mark.parametrize("raw,val", [(b"\x00", 0), (b"\x7f", 127), (b"\x00\x80", 128),
                                     (b"\xff", -1), (b"\x80", -128), (b"\x00\xff\xff", 65535)])
def test_integer(raw, val):
    assert der.decode_integer(raw) == val


def test_integer_empty_rejected():
    with pytest.raises(DerError):
        der.decode_integer(b"")


def test_boolean():
    assert der.decode_boolean(b"\xff") is True
    assert der.decode_boolean(b"\x00") is False
    with pytest.raises(DerError):
        der.decode_boolean(b"\x00\x00")


def test_bit_string():
    assert der.decode_bit_string(b"\x00abc") == (0, b"abc")
    assert der.decode_bit_string(b"\x04\xf0") == (4, b"\xf0")
    for bad in (b"", b"\x08a", b"\x03"):
        with pytest.raises(DerError):
            der.decode_bit_string(bad)


# ---------------------------------------------------------------- times
def _t(tag: int, text: bytes) -> Tlv:
    return read_tlv(bytes([tag, len(text)]) + text)


@pytest.mark.parametrize("tag,text,expected", [
    (der.UTC_TIME, b"491231235959Z", (2049, 12, 31, 23, 59, 59)),   # pivot: 49 -> 2049
    (der.UTC_TIME, b"500101000000Z", (1950, 1, 1, 0, 0, 0)),        # pivot: 50 -> 1950
    (der.UTC_TIME, b"2401021030Z", (2024, 1, 2, 10, 30, 0)),        # seconds omitted (lenient)
    (der.GENERALIZED_TIME, b"20500101000000Z", (2050, 1, 1, 0, 0, 0)),
    (der.GENERALIZED_TIME, b"99991231235959Z", (9999, 12, 31, 23, 59, 59)),
    (der.GENERALIZED_TIME, b"20500101000000.75Z", (2050, 1, 1, 0, 0, 0)),
])
def test_time_valid(tag, text, expected):
    d = der.decode_time(_t(tag, text))
    assert (d.year, d.month, d.day, d.hour, d.minute, d.second) == expected
    assert d.utcoffset().total_seconds() == 0


@pytest.mark.parametrize("tag,text", [
    (der.UTC_TIME, b"491331235959Z"), (der.UTC_TIME, b"491231235960Z"),
    (der.UTC_TIME, b"491231235959"), (der.UTC_TIME, b"491231235959+0100"),
    (der.GENERALIZED_TIME, b"20501301000000Z"), (der.GENERALIZED_TIME, b"2050010100Z"),
    (der.GENERALIZED_TIME, b"\xff\xfe"), (der.UTC_TIME, b""),
])
def test_time_invalid(tag, text):
    with pytest.raises(DerError):
        der.decode_time(_t(tag, text))


def test_time_wrong_tag():
    with pytest.raises(DerError):
        der.decode_time(read_tlv(b"\x0c\x01a"))


# ---------------------------------------------------------------- strings
def _s(tag: int, raw: bytes) -> Tlv:
    return read_tlv(bytes([tag, len(raw)]) + raw)


def test_strings_valid():
    assert der.decode_string(_s(der.UTF8_STRING, "Müller".encode())) == ("Müller", None)
    assert der.decode_string(_s(der.PRINTABLE_STRING, b"abc")) == ("abc", None)
    assert der.decode_string(_s(der.BMP_STRING, "测试".encode("utf-16-be"))) == ("测试", None)
    assert der.decode_string(_s(der.UNIVERSAL_STRING, "x".encode("utf-32-be"))) == ("x", None)
    assert der.decode_string(_s(der.T61_STRING, b"caf\xe9")) == ("café", None)


def test_strings_lenient_with_warning():
    text, warn = der.decode_string(_s(der.UTF8_STRING, b"bad\xff"))
    assert "bad" in text and warn == "invalid_utf8_in_name"
    text, warn = der.decode_string(_s(der.PRINTABLE_STRING, b"caf\xe9"))
    assert text == "café" and warn == "non_ascii_in_ascii_string"
    text, warn = der.decode_string(_s(der.BMP_STRING, b"\xd8\x00\x00"))
    assert warn == "invalid_bmp_string"


def test_non_string_tag_returns_none():
    assert der.decode_string(_s(der.INTEGER, b"\x05")) == (None, None)
