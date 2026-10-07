"""Certificate file content -> structured results (stdlib only). Bytes in, results out, no I/O.

Entry point: parse_cert_bytes(). It never raises for bad content; every problem becomes a
status. Reading files is the scanner's job (Phase 1c), not this module's.

Private-key safety (see also agent/pem.py):
  * The result types hold only parsed certificate facts, small enums and integers. There is
    no field that can carry raw bytes, and no byte offsets are exposed.
  * No flag, count or label says whether a file contained a key or any other non-certificate
    block: a key-only file is reported exactly like an empty or CSR-only file (no_certificate).
  * Format sniffing inspects structural DER headers only (tags, lengths, the PFX version
    integer and its content-type OID).
  * `detail` strings are fixed codes, or fixed messages from the X.509 parser. Exception text
    is never forwarded, because it can quote bytes.
"""
from __future__ import annotations

import pathlib
from dataclasses import dataclass

from .der import BIT_STRING, INTEGER, OID, SEQUENCE, DerError, decode_oid, read_tlv
from .pem import PemError, decode_block, find_certificate_blocks, has_pem_marker
from .x509_parse import CertInfo, CertParseError, parse_certificate

DEFAULT_MAX_CERTS = 1000
DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024

_PKCS7_DATA = "1.2.840.113549.1.7.1"
_PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2"

# Per-entry parse_status values
OK, MALFORMED, UNSUPPORTED, TOO_LARGE = "ok", "malformed", "unsupported", "too_large"
# Additional file-level values
PARTIAL, NO_CERTIFICATE = "partial", "no_certificate"

_EXPECTED_FORMATS = {
    ".pem": {"pem"}, ".der": {"der"},
    ".crt": {"pem", "der"}, ".cer": {"pem", "der"}, ".cert": {"pem", "der"},
    ".pfx": {"pkcs12"}, ".p12": {"pkcs12"},
}


@dataclass(frozen=True)
class CertEntry:
    index: int                      # position among the file's certificates (0-based)
    parse_status: str               # ok | malformed | unsupported | too_large
    detail: str | None              # None when ok; otherwise a fixed code / fixed message
    cert: CertInfo | None

    def to_dict(self) -> dict:
        return {"index": self.index, "parse_status": self.parse_status, "detail": self.detail,
                "cert": self.cert.to_dict() if self.cert else None}


@dataclass(frozen=True)
class FileParse:
    format: str                     # pem | der | pkcs12 | unknown
    file_status: str                # ok | partial | malformed | no_certificate | unsupported | too_large
    detail: str | None
    entries: tuple[CertEntry, ...]
    total_certificates: int         # certificates examined; "at least" when truncated
    truncated: bool                 # more than max_certs certificates; the rest were not examined
    extension_mismatch: bool        # content format differs from what the filename suggests

    def to_dict(self) -> dict:
        return {"format": self.format, "file_status": self.file_status, "detail": self.detail,
                "entries": [e.to_dict() for e in self.entries],
                "total_certificates": self.total_certificates, "truncated": self.truncated,
                "extension_mismatch": self.extension_mismatch}


# ================================================================ sniffing
def _der_kind(data: bytes) -> str | None:
    """'x509' | 'pkcs12' | 'other' for DER-looking data, None if it is not DER.

    Reads headers of the first few elements only; never decodes values except a one-byte
    INTEGER (the PFX version) and an OID (the PFX content type).
    """
    try:
        outer = read_tlv(data, 0)
        if outer.tag != SEQUENCE:
            return None
        kids, pos = [], outer.start
        while pos < outer.end and len(kids) < 4:
            k = read_tlv(data, pos, outer.end)
            kids.append(k)
            pos = k.end
        if (len(kids) == 3 and pos == outer.end and kids[0].tag == SEQUENCE
                and kids[1].tag == SEQUENCE and kids[2].tag == BIT_STRING):
            return "x509"
        if (len(kids) >= 2 and kids[0].tag == INTEGER and kids[0].end - kids[0].start == 1
                and data[kids[0].start] == 3 and kids[1].tag == SEQUENCE):
            content_type = read_tlv(data, kids[1].start, kids[1].end)
            if content_type.tag == OID and decode_oid(content_type.value) in (
                    _PKCS7_DATA, _PKCS7_SIGNED_DATA):
                return "pkcs12"
        return "other"
    except DerError:
        return None


def sniff_format(data: bytes) -> str:
    """'pkcs12' | 'der' | 'pem' | 'unknown', decided by content (the extension is only a hint).

    'der' means well-formed DER that is not a PFX; it need not be a certificate.
    DER is checked before PEM so a DER certificate whose text happens to contain a PEM marker
    is still DER.
    """
    kind = _der_kind(data)
    if kind == "pkcs12":
        return "pkcs12"
    if kind is not None:
        return "der"
    if has_pem_marker(data):
        return "pem"
    return "unknown"


def _extension_mismatch(fmt: str, filename_hint: str | None) -> bool:
    if not filename_hint or fmt not in ("pem", "der", "pkcs12"):
        return False
    expected = _EXPECTED_FORMATS.get(pathlib.PurePath(filename_hint).suffix.lower())
    return expected is not None and fmt not in expected


# ================================================================ parsing
def _entry_from_der(index: int, der: bytes) -> CertEntry:
    try:
        return CertEntry(index, OK, None, parse_certificate(der))
    except CertParseError as e:
        status = e.code if e.code in (UNSUPPORTED, TOO_LARGE) else MALFORMED
        return CertEntry(index, status, f"x509_{e.code}: {e.message}", None)


def _file_status(entries: list[CertEntry]) -> str:
    bad = [e for e in entries if e.parse_status != OK]
    if not bad:
        return "ok"
    if len(bad) < len(entries):
        return PARTIAL
    statuses = {e.parse_status for e in bad}
    return statuses.pop() if len(statuses) == 1 and statuses <= {UNSUPPORTED, TOO_LARGE} else MALFORMED


def _result(fmt, status, detail=None, entries=(), truncated=False, mismatch=False) -> FileParse:
    return FileParse(fmt, status, detail, tuple(entries), len(entries), truncated, mismatch)


def parse_cert_bytes(data: bytes, *, filename_hint: str | None = None,
                     max_certs: int = DEFAULT_MAX_CERTS,
                     max_size: int = DEFAULT_MAX_FILE_BYTES) -> FileParse:
    """Parse the contents of one certificate file. Never raises for bad content."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("parse_cert_bytes expects bytes")
    data = bytes(data)
    try:
        return _parse(data, filename_hint, max_certs, max_size)
    except Exception:                                   # noqa: BLE001 - boundary; fixed message only
        return _result("unknown", "malformed", "internal_error")


def _parse(data: bytes, filename_hint, max_certs: int, max_size: int) -> FileParse:
    if len(data) > max_size:
        return _result("unknown", "too_large", "file_too_large")
    if not data:
        return _result("unknown", NO_CERTIFICATE, "empty_file")
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):          # UTF-16/32 BOM: deliberately not decoded
        return _result("unknown", UNSUPPORTED, "utf16_text_unsupported")

    fmt = sniff_format(data)
    mismatch = _extension_mismatch(fmt, filename_hint)

    if fmt == "pkcs12":
        return _result("pkcs12", UNSUPPORTED, "pkcs12_not_handled_yet", mismatch=mismatch)
    if fmt == "unknown":
        return _result("unknown", MALFORMED, "unrecognized_content")

    if fmt == "der":
        if _der_kind(data) != "x509":
            return _result("der", NO_CERTIFICATE, "der_not_a_certificate", mismatch=mismatch)
        entries = [_entry_from_der(0, data)]
        return _result("der", _file_status(entries), None, entries, mismatch=mismatch)

    blocks, truncated = find_certificate_blocks(data, max_certs)
    if not blocks:
        return _result("pem", NO_CERTIFICATE, "no_certificate_block", mismatch=mismatch)
    entries: list[CertEntry] = []
    for i, block in enumerate(blocks):
        if block.error:
            entries.append(CertEntry(i, MALFORMED, block.error, None))
            continue
        try:
            der = decode_block(block.body)
        except PemError as e:
            entries.append(CertEntry(i, TOO_LARGE if e.code == "pem_body_too_large" else MALFORMED,
                                     e.code, None))
            continue
        entries.append(_entry_from_der(i, der))
    detail = "bundle_truncated" if truncated else None
    return _result("pem", _file_status(entries), detail, entries, truncated, mismatch)
