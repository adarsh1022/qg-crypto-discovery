"""PEM certificate-block extraction (stdlib only). Bytes in, bytes out, no I/O.

Private-key safety is structural here:
  * Blocks are located with regex *markers* only. For any block whose label is not a
    certificate label we record nothing: the body is never sliced, base64-decoded,
    stored, counted or logged. Only the bodies of CERTIFICATE-type blocks are extracted.
  * Nothing in this module reports that a key (or any other non-certificate block) exists.
  * Error codes are fixed strings, never derived from file content.

Linear time: BEGIN and END markers are each found in one regex pass and merged, so a file
with 100,000 markers costs the same as 100,000 lines.
"""
from __future__ import annotations

import binascii
import heapq
import re
from dataclasses import dataclass

CERT_LABELS = frozenset({b"CERTIFICATE", b"X509 CERTIFICATE", b"TRUSTED CERTIFICATE"})

# A marker must start a line (optionally indented, optionally after a UTF-8 BOM at file start).
_BEGIN = re.compile(rb"(?:(?<=[\r\n])|\A(?:\xef\xbb\xbf)?)[ \t]*-----BEGIN ([A-Z0-9 ]{1,64})-----")
_END = re.compile(rb"-----END ([A-Z0-9 ]{1,64})-----")

# base64 of the largest certificate we will parse (1 MiB DER) plus slack for padding
_MAX_B64_BYTES = (1 << 20) * 4 // 3 + 16


class PemError(ValueError):
    """code is one of the fixed strings below; message never contains file content."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class PemBlock:
    """One certificate-labelled block. Exactly one of body / error is set."""
    body: bytes | None      # the base64 text between the markers (certificate data only)
    error: str | None       # pem_unterminated_block | pem_label_mismatch


def has_pem_marker(data: bytes) -> bool:
    """True if any PEM BEGIN marker (of any label) is present. Reveals nothing about the label."""
    return _BEGIN.search(data) is not None


def find_certificate_blocks(data: bytes, max_blocks: int) -> tuple[list[PemBlock], bool]:
    """-> (certificate blocks in file order, truncated).

    `truncated` is True when more than `max_blocks` certificate blocks exist; the extras are
    not examined.
    """
    blocks: list[PemBlock] = []

    def begins():
        for m in _BEGIN.finditer(data):
            yield m.start(), 0, m

    def ends():
        for m in _END.finditer(data):
            yield m.start(), 1, m

    open_label: bytes | None = None
    open_is_cert = False
    body_start = 0

    def add(block: PemBlock) -> bool:
        if len(blocks) >= max_blocks:
            return False
        blocks.append(block)
        return True

    for _pos, kind, m in heapq.merge(begins(), ends(), key=lambda t: t[0]):
        if kind == 0:                                   # BEGIN
            if open_label is not None and open_is_cert:
                if not add(PemBlock(None, "pem_unterminated_block")):
                    return blocks, True
            open_label = m.group(1)
            open_is_cert = open_label in CERT_LABELS
            body_start = m.end()
        else:                                           # END
            if open_label is None:
                continue
            if open_is_cert:
                if m.group(1) == open_label:
                    block = PemBlock(data[body_start:m.start()], None)
                else:
                    block = PemBlock(None, "pem_label_mismatch")
                if not add(block):
                    return blocks, True
            open_label = None

    if open_label is not None and open_is_cert:
        if not add(PemBlock(None, "pem_unterminated_block")):
            return blocks, True
    return blocks, False


def decode_block(body: bytes) -> bytes:
    """Base64 body of a certificate block -> DER bytes. Raises PemError (fixed code)."""
    if b":" in body:                    # RFC 1421 headers (Proc-Type, DEK-Info, ...): not for certificates
        raise PemError("pem_headers_unsupported")
    joined = b"".join(body.split())     # drops all whitespace: spaces, tabs, CR, LF
    if not joined:
        raise PemError("pem_empty_body")
    if len(joined) > _MAX_B64_BYTES:
        raise PemError("pem_body_too_large")
    try:
        return binascii.a2b_base64(joined, strict_mode=True)
    except binascii.Error:
        raise PemError("pem_bad_base64") from None
