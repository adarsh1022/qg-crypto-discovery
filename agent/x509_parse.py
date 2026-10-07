"""X.509 certificate parser (stdlib only). Pure functions: bytes in, facts out, no I/O.

Scope: the fields the discovery report needs. It does not verify signatures, build
chains, check revocation or judge trust. Only public certificate data is read; this
module never handles private keys.

Errors: every failure is a CertParseError with code 'malformed', 'unsupported' or
'too_large'. Anything else escaping this module is a bug.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import math
from dataclasses import dataclass

from . import oids
from .der import (BIT_STRING, BOOLEAN, GENERALIZED_TIME, INTEGER, OCTET_STRING, OID,
                  SEQUENCE, SET, UTC_TIME, DerError, Tlv, children, decode_bit_string,
                  decode_boolean, decode_integer, decode_oid, decode_string, decode_time,
                  read_tlv)

MAX_CERT_BYTES = 1 << 20            # 1 MiB; real certificates are a few KB
DEFAULT_EXPIRING_DAYS = 30

# context-specific tags used inside TBSCertificate / GeneralName
_TAG_VERSION = 0xA0
_TAG_ISSUER_UID = 0x81
_TAG_SUBJECT_UID = 0x82
_TAG_EXTENSIONS = 0xA3


class CertParseError(ValueError):
    """code: 'malformed' | 'unsupported' | 'too_large'."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _malformed(message: str) -> CertParseError:
    return CertParseError("malformed", message)


def _expect(tlv: Tlv, tag: int, what: str) -> None:
    if tlv.tag != tag:
        raise _malformed(f"{what}: expected tag 0x{tag:02x}, found 0x{tlv.tag:02x}")


@dataclass(frozen=True)
class SanEntry:
    type: str     # dns | ip | email | uri | dir_name | other_name | registered_id | x400_address | edi_party
    value: str    # other_name -> its type OID; x400_address / edi_party -> ""


@dataclass(frozen=True)
class CertInfo:
    sha256: str                       # hex SHA-256 of the certificate's DER bytes (identity)
    der_length: int
    trailing_bytes: int               # bytes after the certificate (not part of the fingerprint)
    version: int                      # 1, 2 or 3
    serial_hex: str                   # lowercase hex, no padding; '-' prefix if (invalidly) negative
    subject: str                      # RFC 4514 string
    issuer: str
    not_before: dt.datetime           # timezone-aware UTC
    not_after: dt.datetime
    key_algorithm: str                # 'RSA', 'EC', 'Ed25519', ... or the dotted OID if unknown
    key_algorithm_oid: str
    key_size: int | None              # bits; None when not applicable / not determinable
    key_curve: str | None             # for EC keys
    signature_algorithm: str
    signature_algorithm_oid: str
    san: tuple[SanEntry, ...]
    is_ca: bool | None                # BasicConstraints.cA; None when the extension is absent
    path_length: int | None
    is_self_issued: bool              # issuer and subject encodings are byte-identical
    warnings: tuple[str, ...]         # non-fatal oddities; any warning means reduced confidence

    def to_dict(self) -> dict:
        def iso(d: dt.datetime) -> str:
            return d.strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "sha256": self.sha256, "der_length": self.der_length,
            "trailing_bytes": self.trailing_bytes, "version": self.version,
            "serial_hex": self.serial_hex, "subject": self.subject, "issuer": self.issuer,
            "not_before": iso(self.not_before), "not_after": iso(self.not_after),
            "key_algorithm": self.key_algorithm, "key_algorithm_oid": self.key_algorithm_oid,
            "key_size": self.key_size, "key_curve": self.key_curve,
            "signature_algorithm": self.signature_algorithm,
            "signature_algorithm_oid": self.signature_algorithm_oid,
            "san": [{"type": s.type, "value": s.value} for s in self.san],
            "is_ca": self.is_ca, "path_length": self.path_length,
            "is_self_issued": self.is_self_issued, "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class Validity:
    days_to_expiry: int       # floor((not_after - now) / 1 day); negative once expired
    status: str               # 'valid' | 'expiring' | 'expired'
    not_yet_valid: bool       # separate flag: now < not_before


def assess_validity(not_before: dt.datetime, not_after: dt.datetime, now: dt.datetime,
                    expiring_days: int = DEFAULT_EXPIRING_DAYS) -> Validity:
    """Classify a certificate at time `now`.

    expired  : now > not_after
    expiring : not expired and days_to_expiry <= expiring_days (inclusive)
    valid    : otherwise
    not_yet_valid is reported separately and does not change `status`.
    """
    if now.tzinfo is None or not_before.tzinfo is None or not_after.tzinfo is None:
        raise ValueError("assess_validity needs timezone-aware datetimes")
    days = math.floor((not_after - now).total_seconds() / 86400)
    if now > not_after:
        status = "expired"
    elif days <= expiring_days:
        status = "expiring"
    else:
        status = "valid"
    return Validity(days, status, now < not_before)


# ================================================================ public entry point
def parse_certificate(data: bytes, *, max_size: int = MAX_CERT_BYTES) -> CertInfo:
    """Parse one DER-encoded X.509 certificate. Raises CertParseError on any problem."""
    data = bytes(data)
    if not data:
        raise _malformed("empty input")
    if len(data) > max_size:
        raise CertParseError("too_large", f"{len(data)} bytes exceeds limit of {max_size}")
    try:
        return _parse(data)
    except DerError as e:
        raise _malformed(str(e)) from None


# ================================================================ internals
def _parse(data: bytes) -> CertInfo:
    warnings: list[str] = []
    cert = read_tlv(data, 0)
    _expect(cert, SEQUENCE, "certificate")
    cert_der = data[:cert.end]
    trailing = len(data) - cert.end
    if trailing:
        warnings.append("trailing_data_after_certificate")

    parts = children(cert)
    if len(parts) != 3:
        raise _malformed("certificate must have exactly three elements")
    tbs, outer_sig_alg, sig_value = parts
    _expect(tbs, SEQUENCE, "tbsCertificate")
    _expect(sig_value, BIT_STRING, "signatureValue")

    fields = children(tbs)
    i = 0
    version = 1
    if fields and fields[0].tag == _TAG_VERSION:
        inner = children(fields[0])
        if len(inner) != 1 or inner[0].tag != INTEGER:
            raise _malformed("invalid version field")
        v = decode_integer(inner[0].value)
        if v not in (0, 1, 2):
            raise CertParseError("unsupported", f"unknown certificate version {v + 1}")
        version = v + 1
        i = 1
    if len(fields) - i < 6:
        raise _malformed("tbsCertificate is missing required fields")
    serial_tlv, tbs_sig_alg, issuer_tlv, validity_tlv, subject_tlv, spki_tlv = fields[i:i + 6]

    # serial number
    _expect(serial_tlv, INTEGER, "serialNumber")
    serial = decode_integer(serial_tlv.value)
    serial_hex = ("-" if serial < 0 else "") + format(abs(serial), "x")
    if serial <= 0:
        warnings.append("serial_not_positive")
    elif len(serial_tlv.value) > 21:        # 20 octets plus one possible sign-padding octet
        warnings.append("serial_longer_than_20_octets")

    # signature algorithm
    sig_oid, sig_params = _algorithm_identifier(outer_sig_alg, "signatureAlgorithm")
    tbs_sig_oid, _ = _algorithm_identifier(tbs_sig_alg, "tbsCertificate.signature")
    if tbs_sig_oid != sig_oid:
        warnings.append("signature_algorithm_mismatch")
    sig_name = _signature_name(sig_oid, sig_params, warnings)

    # names
    issuer = _name_to_string(issuer_tlv, warnings)
    subject = _name_to_string(subject_tlv, warnings)

    # validity
    _expect(validity_tlv, SEQUENCE, "validity")
    times = children(validity_tlv)
    if len(times) != 2 or any(t.tag not in (UTC_TIME, GENERALIZED_TIME) for t in times):
        raise _malformed("validity must be two UTCTime/GeneralizedTime values")
    not_before, not_after = decode_time(times[0]), decode_time(times[1])
    if not_after < not_before:
        warnings.append("validity_end_before_start")

    # public key
    key_name, key_oid, key_size, key_curve = _public_key(spki_tlv, warnings)

    # optional trailing TBS fields
    extensions: dict[str, bytes] = {}
    seen_ext = False
    for item in fields[i + 6:]:
        if item.tag in (_TAG_ISSUER_UID, _TAG_SUBJECT_UID):
            continue
        if item.tag == _TAG_EXTENSIONS and not seen_ext:
            extensions = _extensions(item, warnings)
            seen_ext = True
        else:
            raise _malformed(f"unexpected field with tag 0x{item.tag:02x} in tbsCertificate")

    san: tuple[SanEntry, ...] = ()
    if oids.EXT_SUBJECT_ALT_NAME in extensions:
        san = _subject_alt_name(extensions[oids.EXT_SUBJECT_ALT_NAME], warnings)
    is_ca = None
    path_length = None
    if oids.EXT_BASIC_CONSTRAINTS in extensions:
        is_ca, path_length = _basic_constraints(extensions[oids.EXT_BASIC_CONSTRAINTS])

    return CertInfo(
        sha256=hashlib.sha256(cert_der).hexdigest(), der_length=len(cert_der),
        trailing_bytes=trailing, version=version, serial_hex=serial_hex,
        subject=subject, issuer=issuer, not_before=not_before, not_after=not_after,
        key_algorithm=key_name, key_algorithm_oid=key_oid, key_size=key_size,
        key_curve=key_curve, signature_algorithm=sig_name, signature_algorithm_oid=sig_oid,
        san=san, is_ca=is_ca, path_length=path_length,
        is_self_issued=issuer_tlv.raw == subject_tlv.raw,
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _algorithm_identifier(tlv: Tlv, what: str) -> tuple[str, Tlv | None]:
    _expect(tlv, SEQUENCE, what)
    kids = children(tlv)
    if not 1 <= len(kids) <= 2 or kids[0].tag != OID:
        raise _malformed(f"{what}: invalid AlgorithmIdentifier")
    return decode_oid(kids[0].value), (kids[1] if len(kids) == 2 else None)


def _signature_name(oid: str, params: Tlv | None, warnings: list[str]) -> str:
    name = oids.SIGNATURE_ALGORITHMS.get(oid)
    if name is None:
        warnings.append("unknown_signature_algorithm")
        return oid
    if oid == oids.RSASSA_PSS:
        try:
            if params is not None and params.tag == SEQUENCE:
                for kid in children(params):
                    if kid.tag == 0xA0:                       # [0] hashAlgorithm
                        inner = children(kid)
                        hash_oid, _ = _algorithm_identifier(inner[0], "pss.hashAlgorithm")
                        return f"RSASSA-PSS ({oids.HASHES.get(hash_oid, hash_oid)})"
        except (DerError, CertParseError, IndexError):
            warnings.append("bad_rsassa_pss_parameters")
    return name


# ---------------------------------------------------------------- distinguished names
def _escape_rfc4514(value: str) -> str:
    if not value:
        return ""
    value = value.replace("\\", "\\\\")
    for ch in ('"', "+", ",", ";", "<", ">"):
        value = value.replace(ch, "\\" + ch)
    value = value.replace("\x00", "\\00")
    if value[0] in ("#", " "):
        value = "\\" + value
    if value[-1] == " ":
        value = value[:-1] + "\\ "
    return value


def _name_to_string(tlv: Tlv, warnings: list[str]) -> str:
    """RFC 4514 string: RDNs most-specific first (reverse of encoding order)."""
    _expect(tlv, SEQUENCE, "Name")
    rdns: list[str] = []
    for rdn in children(tlv):
        _expect(rdn, SET, "RelativeDistinguishedName")
        attrs = children(rdn)
        if not attrs:
            raise _malformed("empty RelativeDistinguishedName")
        parts = []
        for atv in attrs:
            _expect(atv, SEQUENCE, "AttributeTypeAndValue")
            kv = children(atv)
            if len(kv) != 2 or kv[0].tag != OID:
                raise _malformed("invalid AttributeTypeAndValue")
            oid = decode_oid(kv[0].value)
            text, warn = decode_string(kv[1])
            if warn:
                warnings.append(warn)
            value = "#" + kv[1].raw.hex() if text is None else _escape_rfc4514(text)
            parts.append(f"{oids.NAME_ATTRIBUTES_RFC4514.get(oid, oid)}={value}")
        rdns.append("+".join(parts))
    return ",".join(reversed(rdns))


# ---------------------------------------------------------------- public key
def _public_key(spki: Tlv, warnings: list[str]) -> tuple[str, str, int | None, str | None]:
    _expect(spki, SEQUENCE, "subjectPublicKeyInfo")
    kids = children(spki)
    if len(kids) != 2 or kids[1].tag != BIT_STRING:
        raise _malformed("invalid subjectPublicKeyInfo")
    oid, params = _algorithm_identifier(kids[0], "subjectPublicKeyInfo.algorithm")
    unused, key_bytes = decode_bit_string(kids[1].value)
    name = oids.PUBLIC_KEY_ALGORITHMS.get(oid)
    size: int | None = None
    curve: str | None = None
    if name is None:
        warnings.append("unknown_public_key_algorithm")
        name = oid
    elif oid in (oids.RSA_ENCRYPTION, oids.RSASSA_PSS):
        size = _rsa_bits(unused, key_bytes, warnings)
    elif oid == oids.EC_PUBLIC_KEY:
        curve, size = _ec_curve(params, warnings)
    elif oid == oids.DSA:
        size = _dsa_bits(params)
    elif oid in oids.FIXED_KEY_SIZES:
        size = oids.FIXED_KEY_SIZES[oid]
    return name, oid, size, curve


def _rsa_bits(unused: int, key_bytes: bytes, warnings: list[str]) -> int:
    if unused:
        raise _malformed("RSA public key has unused bits")
    seq = read_tlv(key_bytes, 0)
    _expect(seq, SEQUENCE, "RSAPublicKey")
    kids = children(seq)
    if len(kids) != 2 or any(k.tag != INTEGER for k in kids):
        raise _malformed("invalid RSAPublicKey")
    raw = kids[0].value
    if not raw:
        raise _malformed("empty RSA modulus")
    if raw[0] & 0x80:
        # Some real certificates (e.g. Microsoft's "Root Agency" test root) encode the modulus
        # without the leading 0x00, which strict DER reads as negative. The certificate is
        # otherwise fine, so report it using the unsigned value and flag the defect.
        warnings.append("rsa_modulus_encoded_as_negative")
    bits = int.from_bytes(raw, "big").bit_length()
    if bits == 0:
        raise _malformed("RSA modulus is zero")
    return bits


def _ec_curve(params: Tlv | None, warnings: list[str]) -> tuple[str | None, int | None]:
    if params is None:
        warnings.append("ec_parameters_missing")
        return None, None
    if params.tag == OID:
        oid = decode_oid(params.value)
        if oid in oids.CURVES:
            return oids.CURVES[oid]
        warnings.append("unknown_ec_curve")
        return oid, None
    warnings.append("ec_explicit_or_implicit_parameters")
    return "explicit-parameters", None


def _dsa_bits(params: Tlv | None) -> int | None:
    if params is None or params.tag != SEQUENCE:
        return None
    kids = children(params)
    if len(kids) < 1 or kids[0].tag != INTEGER:
        raise _malformed("invalid DSA parameters")
    p = decode_integer(kids[0].value)
    return p.bit_length() if p > 0 else None


# ---------------------------------------------------------------- extensions
def _extensions(wrapper: Tlv, warnings: list[str]) -> dict[str, bytes]:
    inner = children(wrapper)
    if len(inner) != 1:
        raise _malformed("invalid extensions wrapper")
    _expect(inner[0], SEQUENCE, "extensions")
    found: dict[str, bytes] = {}
    for ext in children(inner[0]):
        _expect(ext, SEQUENCE, "extension")
        kids = children(ext)
        if len(kids) not in (2, 3) or kids[0].tag != OID:
            raise _malformed("invalid extension")
        if len(kids) == 3 and kids[1].tag != BOOLEAN:
            raise _malformed("invalid extension critical flag")
        if kids[-1].tag != OCTET_STRING:
            raise _malformed("extension value is not an OCTET STRING")
        oid = decode_oid(kids[0].value)
        if oid in found:
            warnings.append("duplicate_extension")
            continue
        found[oid] = kids[-1].value
    return found


def _basic_constraints(value: bytes) -> tuple[bool, int | None]:
    seq = read_tlv(value, 0)
    _expect(seq, SEQUENCE, "BasicConstraints")
    if seq.end != len(value):
        raise _malformed("trailing data in BasicConstraints")
    kids = children(seq)
    ca = False
    path_len: int | None = None
    idx = 0
    if idx < len(kids) and kids[idx].tag == BOOLEAN:
        ca = decode_boolean(kids[idx].value)
        idx += 1
    if idx < len(kids) and kids[idx].tag == INTEGER:
        path_len = decode_integer(kids[idx].value)
        if path_len < 0:
            raise _malformed("negative pathLenConstraint")
        idx += 1
    if idx != len(kids):
        raise _malformed("invalid BasicConstraints")
    return ca, path_len


def _subject_alt_name(value: bytes, warnings: list[str]) -> tuple[SanEntry, ...]:
    seq = read_tlv(value, 0)
    _expect(seq, SEQUENCE, "SubjectAltName")
    if seq.end != len(value):
        raise _malformed("trailing data in SubjectAltName")
    return tuple(_general_name(k, warnings) for k in children(seq))


def _ia5(tlv: Tlv, warnings: list[str]) -> str:
    try:
        return tlv.value.decode("ascii")
    except UnicodeDecodeError:
        warnings.append("non_ascii_in_san")
        return tlv.value.decode("latin-1")


def _general_name(tlv: Tlv, warnings: list[str]) -> SanEntry:
    t = tlv.tag
    if t == 0x82:
        return SanEntry("dns", _ia5(tlv, warnings))
    if t == 0x81:
        return SanEntry("email", _ia5(tlv, warnings))
    if t == 0x86:
        return SanEntry("uri", _ia5(tlv, warnings))
    if t == 0x87:
        raw = tlv.value
        if len(raw) == 4:
            return SanEntry("ip", str(ipaddress.IPv4Address(raw)))
        if len(raw) == 16:
            return SanEntry("ip", str(ipaddress.IPv6Address(raw)))
        raise _malformed("iPAddress must be 4 or 16 octets")
    if t == 0xA4:
        kids = children(tlv)
        if len(kids) != 1:
            raise _malformed("invalid directoryName")
        return SanEntry("dir_name", _name_to_string(kids[0], warnings))
    if t == 0xA0:
        kids = children(tlv)
        if not kids or kids[0].tag != OID:
            raise _malformed("invalid otherName")
        return SanEntry("other_name", decode_oid(kids[0].value))
    if t == 0x88:
        return SanEntry("registered_id", decode_oid(tlv.value))
    if t == 0xA3:
        return SanEntry("x400_address", "")
    if t == 0xA5:
        return SanEntry("edi_party", "")
    raise _malformed(f"unknown GeneralName tag 0x{t:02x}")
