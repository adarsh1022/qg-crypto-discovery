"""Minimal DER reader (stdlib only).

Design rules, because certificate files are untrusted input:
  * every read is bounds-checked against an explicit end offset;
  * no recursion anywhere (callers walk fixed-depth structures with children());
  * indefinite lengths and high-tag-number tags are rejected (X.509 uses neither);
  * only ValueError subclass DerError escapes, never IndexError/UnicodeError.

Lenient where real-world certificates are sloppy (non-minimal lengths, BER-style
booleans, invalid UTF-8 in names); strict where leniency could hide corruption.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass

# universal tags (identifier octets)
BOOLEAN = 0x01
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
UTF8_STRING = 0x0C
NUMERIC_STRING = 0x12
PRINTABLE_STRING = 0x13
T61_STRING = 0x14
IA5_STRING = 0x16
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18
VISIBLE_STRING = 0x1A
UNIVERSAL_STRING = 0x1C
BMP_STRING = 0x1E
SEQUENCE = 0x30
SET = 0x31

MAX_OID_BYTES = 128


class DerError(ValueError):
    """Malformed or unsupported DER."""


@dataclass(frozen=True, slots=True, eq=False)
class Tlv:
    """One tag-length-value element. Holds offsets into a shared buffer (no copying)."""
    buf: bytes
    tag: int
    head: int    # offset of the identifier octet
    start: int   # offset of first content byte
    end: int     # offset just past the last content byte

    @property
    def value(self) -> bytes:
        return self.buf[self.start:self.end]

    @property
    def raw(self) -> bytes:
        """The complete encoding including tag and length."""
        return self.buf[self.head:self.end]


def read_tlv(buf: bytes, pos: int = 0, end: int | None = None) -> Tlv:
    """Read one TLV starting at `pos`, never reading at or past `end`."""
    if end is None:
        end = len(buf)
    if pos < 0 or pos + 2 > end:
        raise DerError("truncated element header")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise DerError("high-tag-number form is not supported")
    first = buf[pos + 1]
    p = pos + 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DerError("indefinite length is not allowed in DER")
    else:
        n = first & 0x7F
        if n > 4:
            raise DerError("length field too large")
        if p + n > end:
            raise DerError("truncated length field")
        length = int.from_bytes(buf[p:p + n], "big")
        p += n
    if p + length > end:
        raise DerError("element length exceeds enclosing data")
    return Tlv(buf, tag, pos, p, p + length)


def children(parent: Tlv) -> list[Tlv]:
    """Parse a constructed element's content as a run of TLVs that consumes it exactly."""
    out: list[Tlv] = []
    pos = parent.start
    while pos < parent.end:
        child = read_tlv(parent.buf, pos, parent.end)
        out.append(child)
        pos = child.end
    return out


# ---------------------------------------------------------------- primitive decoders
def decode_oid(value: bytes) -> str:
    if not value:
        raise DerError("empty OID")
    if len(value) > MAX_OID_BYTES:
        raise DerError("OID too long")
    if value[-1] & 0x80:
        raise DerError("truncated OID")
    arcs: list[int] = []
    n = 0
    first = True
    for b in value:
        n = (n << 7) | (b & 0x7F)
        if b & 0x80:
            continue
        if first:
            if n < 40:
                arcs += [0, n]
            elif n < 80:
                arcs += [1, n - 40]
            else:
                arcs += [2, n - 80]
            first = False
        else:
            arcs.append(n)
        n = 0
    return ".".join(map(str, arcs))


def decode_integer(value: bytes) -> int:
    if not value:
        raise DerError("empty INTEGER")
    return int.from_bytes(value, "big", signed=True)


def decode_boolean(value: bytes) -> bool:
    if len(value) != 1:
        raise DerError("BOOLEAN must be one octet")
    return value[0] != 0


def decode_bit_string(value: bytes) -> tuple[int, bytes]:
    """-> (unused_bits, data)."""
    if not value:
        raise DerError("empty BIT STRING")
    unused = value[0]
    if unused > 7 or (len(value) == 1 and unused != 0):
        raise DerError("invalid BIT STRING padding")
    return unused, value[1:]


_UTC_RE = re.compile(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z")
_GEN_RE = re.compile(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:[.,]\d+)?Z")


def decode_time(tlv: Tlv) -> dt.datetime:
    """UTCTime / GeneralizedTime -> timezone-aware UTC datetime (RFC 5280 rules)."""
    try:
        text = tlv.value.decode("ascii")
    except UnicodeDecodeError:
        raise DerError("time value is not ASCII") from None
    if tlv.tag == UTC_TIME:
        m = _UTC_RE.fullmatch(text)
        if not m:
            raise DerError("malformed UTCTime")
        yy = int(m[1])
        year = yy + (1900 if yy >= 50 else 2000)      # RFC 5280 4.1.2.5.1 pivot
        rest = (m[2], m[3], m[4], m[5], m[6] or "00")
    elif tlv.tag == GENERALIZED_TIME:
        m = _GEN_RE.fullmatch(text)
        if not m:
            raise DerError("malformed GeneralizedTime")
        year = int(m[1])
        rest = (m[2], m[3], m[4], m[5], m[6])
    else:
        raise DerError(f"unexpected time tag 0x{tlv.tag:02x}")
    try:
        return dt.datetime(year, *(int(x) for x in rest), tzinfo=dt.timezone.utc)
    except ValueError as e:
        raise DerError(f"invalid date/time: {e}") from None


def decode_string(tlv: Tlv) -> tuple[str | None, str | None]:
    """Decode a character-string element.

    -> (text, warning). `text` is None for a non-string tag (caller decides how to render it).
    A warning is returned when the bytes were not valid for the declared type and had to be
    decoded leniently; the certificate is still reported, at reduced confidence.
    """
    t, v = tlv.tag, tlv.value
    if t == UTF8_STRING:
        try:
            return v.decode("utf-8"), None
        except UnicodeDecodeError:
            return v.decode("utf-8", "replace"), "invalid_utf8_in_name"
    if t in (PRINTABLE_STRING, NUMERIC_STRING, IA5_STRING, VISIBLE_STRING):
        try:
            return v.decode("ascii"), None
        except UnicodeDecodeError:
            return v.decode("latin-1"), "non_ascii_in_ascii_string"
    if t == T61_STRING:
        return v.decode("latin-1"), None
    if t == BMP_STRING:
        try:
            return v.decode("utf-16-be"), None
        except UnicodeDecodeError:
            return v.decode("utf-16-be", "replace"), "invalid_bmp_string"
    if t == UNIVERSAL_STRING:
        try:
            return v.decode("utf-32-be"), None
        except UnicodeDecodeError:
            return v.decode("utf-32-be", "replace"), "invalid_universal_string"
    return None, None
