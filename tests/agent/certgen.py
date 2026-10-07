"""Test-only certificate factory (uses `cryptography`; the agent itself never imports it).

Every case is built deterministically except for the key material, which is generated
once per process and cached. Nothing is written to disk: callers get DER bytes.

CASES maps a case name to (builder, expected) where `expected` holds a few facts that
are asserted *independently of the oracle*, so the oracle comparison is not circular.
"""
from __future__ import annotations

import datetime as dt
import functools
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID, ObjectIdentifier

UTC = dt.timezone.utc
NB = dt.datetime(2024, 1, 1, tzinfo=UTC)
NA = dt.datetime(2034, 1, 1, tzinfo=UTC)

_HASHES = {"sha1": hashes.SHA1, "sha224": hashes.SHA224, "sha256": hashes.SHA256,
           "sha384": hashes.SHA384, "sha512": hashes.SHA512}


@functools.lru_cache(maxsize=None)
def key(kind: str):
    if kind.startswith("rsa"):
        return rsa.generate_private_key(65537, int(kind[3:]))
    curves = {"p224": ec.SECP224R1, "p256": ec.SECP256R1, "p384": ec.SECP384R1,
              "p521": ec.SECP521R1, "k256": ec.SECP256K1, "bp256": ec.BrainpoolP256R1}
    if kind in curves:
        return ec.generate_private_key(curves[kind]())
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if kind == "ed448":
        return ed448.Ed448PrivateKey.generate()
    if kind == "dsa2048":
        return dsa.generate_private_key(2048)
    raise KeyError(kind)


def name(cn=None, *attrs, rdns=None) -> x509.Name:
    if rdns is not None:
        return x509.Name(rdns)
    items = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] if cn is not None else []
    return x509.Name(items + list(attrs))


def make(subject, key_kind="rsa2048", *, sign_kind=None, issuer=None, serial=1234567,
         nb=NB, na=NA, hash_alg="sha256", pss=False, san=None, san_critical=False,
         bc=None) -> bytes:
    k, sk = key(key_kind), key(sign_kind or key_kind)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
         .public_key(k.public_key()).serial_number(serial)
         .not_valid_before(nb).not_valid_after(na))
    if san is not None:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=san_critical)
    if bc is not None:
        b = b.add_extension(x509.BasicConstraints(ca=bc[0], path_length=bc[1]), critical=True)
    if isinstance(sk, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        cert = b.sign(sk, None)
    elif pss:
        h = _HASHES[hash_alg]()
        cert = b.sign(sk, h, rsa_padding=padding.PSS(padding.MGF1(h), h.digest_size))
    else:
        cert = b.sign(sk, _HASHES[hash_alg]())
    return cert.public_bytes(serialization.Encoding.DER)


CASES: dict[str, tuple] = {}


def case(case_name, builder, **expected):
    CASES[case_name] = (builder, expected)


# ---- public key types and sizes ---------------------------------------------------------
for _kind, _alg, _size, _curve in [
    ("rsa1024", "RSA", 1024, None), ("rsa2048", "RSA", 2048, None),
    ("rsa3072", "RSA", 3072, None), ("rsa4096", "RSA", 4096, None),
    ("p224", "EC", 224, "P-224"), ("p256", "EC", 256, "P-256"),
    ("p384", "EC", 384, "P-384"), ("p521", "EC", 521, "P-521"),
    ("k256", "EC", 256, "secp256k1"), ("bp256", "EC", 256, "brainpoolP256r1"),
    ("ed25519", "Ed25519", 256, None), ("ed448", "Ed448", 456, None),
    ("dsa2048", "DSA", 2048, None),
]:
    case(f"key_{_kind}", (lambda k=_kind: make(name(f"key-{k}"), k)),
         key_algorithm=_alg, key_size=_size, key_curve=_curve)

# ---- signature algorithms ---------------------------------------------------------------
# `cryptography` refuses to *sign* with SHA-1 / MD5, but weak algorithms are exactly what a
# discovery tool must report. So those fixtures are built by swapping the signature
# AlgorithmIdentifier of a SHA-256 certificate with the tiny independent re-encoder below.
# The signature bytes are then not valid for that algorithm; neither parser verifies signatures.
def _read(buf, pos):
    length, p = buf[pos + 1], pos + 2
    if length & 0x80:
        n = length & 0x7F
        length, p = int.from_bytes(buf[p:p + n], "big"), p + n
    return buf[pos], p, p + length


def _enc(tag, content):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


def _raw_children(buf, start, end):
    out, pos = [], start
    while pos < end:
        _, _, e = _read(buf, pos)
        out.append(buf[pos:e])
        pos = e
    return out


def with_signature_algorithm(der: bytes, algid_der: bytes) -> bytes:
    _, s, e = _read(der, 0)
    tbs, _old_alg, sig = _raw_children(der, s, e)
    _, ts, te = _read(tbs, 0)
    fields = _raw_children(tbs, ts, te)
    fields[2 if fields[0][0] == 0xA0 else 1] = algid_der      # [version], serial, *signature*
    return _enc(0x30, _enc(0x30, b"".join(fields)) + algid_der + sig)


_ALGID = {   # AlgorithmIdentifier DER for algorithms we cannot sign with
    "rsa_sha1": _enc(0x30, _enc(6, bytes.fromhex("2a864886f70d010105")) + b"\x05\x00"),
    "rsa_md5": _enc(0x30, _enc(6, bytes.fromhex("2a864886f70d010104")) + b"\x05\x00"),
    "ecdsa_sha1": _enc(0x30, _enc(6, bytes.fromhex("2a8648ce3d0401"))),
}
case("sig_rsa_sha1", lambda: with_signature_algorithm(
    make(name("rsa-sha1"), "rsa2048"), _ALGID["rsa_sha1"]), signature_algorithm="sha1WithRSAEncryption")
case("sig_rsa_md5", lambda: with_signature_algorithm(
    make(name("rsa-md5"), "rsa2048"), _ALGID["rsa_md5"]), signature_algorithm="md5WithRSAEncryption")
case("sig_ecdsa_sha1", lambda: with_signature_algorithm(
    make(name("ecdsa-sha1"), "p256"), _ALGID["ecdsa_sha1"]), signature_algorithm="ecdsa-with-SHA1")
for _h in ("sha224", "sha256", "sha384", "sha512"):
    case(f"sig_rsa_{_h}", (lambda h=_h: make(name(f"rsa-{h}"), "rsa2048", hash_alg=h)),
         signature_algorithm=f"{_h}WithRSAEncryption")
    case(f"sig_ecdsa_{_h}", (lambda h=_h: make(name(f"ecdsa-{h}"), "p256", hash_alg=h)),
         signature_algorithm=f"ecdsa-with-{_h.upper()}")
case("sig_rsa_pss_sha256", lambda: make(name("pss256"), "rsa2048", pss=True),
     signature_algorithm="RSASSA-PSS (SHA-256)")
case("sig_rsa_pss_sha384", lambda: make(name("pss384"), "rsa2048", pss=True, hash_alg="sha384"),
     signature_algorithm="RSASSA-PSS (SHA-384)")
case("sig_dsa_sha256", lambda: make(name("dsa"), "dsa2048"), signature_algorithm="dsa-with-sha256")
case("sig_ed25519", lambda: make(name("ed"), "ed25519"), signature_algorithm="Ed25519")

# ---- names: string types, escaping, multi-valued RDNs, empty ----------------------------
_CN = NameOID.COMMON_NAME
_NA = x509.NameAttribute
_RDN = x509.RelativeDistinguishedName
case("name_unicode_utf8", lambda: make(name("Müller GmbH – 测试")),
     subject="CN=Müller GmbH – 测试")
for _t in (_ASN1Type.BMPString, _ASN1Type.PrintableString, _ASN1Type.IA5String,
           _ASN1Type.UniversalString, _ASN1Type.T61String, _ASN1Type.UTF8String):
    case(f"name_type_{_t.name}",
         (lambda t=_t: make(name(rdns=[_RDN([_NA(_CN, "plain text", _type=t)])]))),
         subject="CN=plain text")
case("name_specials", lambda: make(name('a,b+c"d\\e;f<g>h')),
     subject='CN=a\\,b\\+c\\"d\\\\e\\;f\\<g\\>h')
case("name_leading_hash", lambda: make(name("#lead")), subject="CN=\\#lead")
case("name_leading_space", lambda: make(name(" lead")), subject="CN=\\ lead")
case("name_trailing_space", lambda: make(name("trail ")), subject="CN=trail\\ ")
case("name_multi_rdn", lambda: make(name(rdns=[
    _RDN([_NA(NameOID.ORGANIZATION_NAME, "Acme")]),
    _RDN([_NA(_CN, "svc"), _NA(NameOID.ORGANIZATIONAL_UNIT_NAME, "Ops")])])),
     subject="CN=svc+OU=Ops,O=Acme")
case("name_many_attributes", lambda: make(name(rdns=[
    _RDN([_NA(NameOID.COUNTRY_NAME, "DE")]), _RDN([_NA(NameOID.STATE_OR_PROVINCE_NAME, "Bavaria")]),
    _RDN([_NA(NameOID.LOCALITY_NAME, "Munich")]), _RDN([_NA(NameOID.ORGANIZATION_NAME, "Acme AG")]),
    _RDN([_NA(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI")]), _RDN([_NA(_CN, "many")]),
    _RDN([_NA(NameOID.EMAIL_ADDRESS, "pki@example.com")]),
    _RDN([_NA(NameOID.SERIAL_NUMBER, "42")]), _RDN([_NA(NameOID.DOMAIN_COMPONENT, "example")]),
    _RDN([_NA(NameOID.USER_ID, "u1")]), _RDN([_NA(NameOID.ORGANIZATION_IDENTIFIER, "VATDE-1")])])),
     subject=("2.5.4.97=VATDE-1,UID=u1,DC=example,2.5.4.5=42,1.2.840.113549.1.9.1=pki@example.com,"
              "CN=many,OU=PKI,O=Acme AG,L=Munich,ST=Bavaria,C=DE"))
case("name_empty_subject_with_san", lambda: make(
    name(rdns=[]), san=[x509.DNSName("empty.example")], san_critical=True),
     subject="", san=[("dns", "empty.example")])
case("name_issued_by_other", lambda: make(
    name("leaf"), "rsa2048", sign_kind="p256", issuer=name("Root CA")),
     subject="CN=leaf", issuer="CN=Root CA", is_self_issued=False)
case("name_self_issued", lambda: make(name("self")), is_self_issued=True)

# ---- serial numbers ---------------------------------------------------------------------
for _label, _serial, _hex in [
    ("1", 1, "1"), ("0x7f", 0x7F, "7f"), ("0x80_needs_padding", 0x80, "80"),
    ("0xff", 0xFF, "ff"), ("0x0100", 0x100, "100"),
    ("max_159_bits", (1 << 159) - 1, format((1 << 159) - 1, "x")),
    ("large_158_bits", (1 << 158) + 12345, format((1 << 158) + 12345, "x")),
]:
    case(f"serial_{_label}", (lambda s=_serial: make(name("serial"), serial=s)), serial_hex=_hex)

# ---- validity dates (UTCTime vs GeneralizedTime boundaries) ------------------------------
for _label, _nb, _na in [
    ("1950", dt.datetime(1950, 1, 1, tzinfo=UTC), dt.datetime(2030, 1, 1, tzinfo=UTC)),
    ("2049_end", dt.datetime(2040, 1, 1, tzinfo=UTC), dt.datetime(2049, 12, 31, 23, 59, 59, tzinfo=UTC)),
    ("2050_start", dt.datetime(2040, 1, 1, tzinfo=UTC), dt.datetime(2050, 1, 1, tzinfo=UTC)),
    ("9999", dt.datetime(2024, 1, 1, tzinfo=UTC), dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)),
    ("expired", dt.datetime(2010, 1, 1, tzinfo=UTC), dt.datetime(2011, 1, 1, tzinfo=UTC)),
    ("future", dt.datetime(2090, 1, 1, tzinfo=UTC), dt.datetime(2095, 1, 1, tzinfo=UTC)),
]:
    case(f"dates_{_label}", (lambda a=_nb, b=_na: make(name("dates"), nb=a, na=b)),
         not_before=_nb, not_after=_na)

# ---- subject alternative names -----------------------------------------------------------
case("san_dns", lambda: make(name("san"), san=[x509.DNSName("example.com"), x509.DNSName("*.example.org")]),
     san=[("dns", "example.com"), ("dns", "*.example.org")])
case("san_ip", lambda: make(name("san"), san=[x509.IPAddress(ipaddress.ip_address("192.0.2.1")),
                                              x509.IPAddress(ipaddress.ip_address("2001:db8::1"))]),
     san=[("ip", "192.0.2.1"), ("ip", "2001:db8::1")])
case("san_email_uri", lambda: make(name("san"), san=[x509.RFC822Name("a@example.com"),
                                                     x509.UniformResourceIdentifier("https://example.com/x")]),
     san=[("email", "a@example.com"), ("uri", "https://example.com/x")])
case("san_dirname", lambda: make(name("san"), san=[x509.DirectoryName(name("dir"))]),
     san=[("dir_name", "CN=dir")])
case("san_other_name", lambda: make(name("san"), san=[x509.OtherName(
    ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), b"\x0c\x05a@b.c")]),
     san=[("other_name", "1.3.6.1.4.1.311.20.2.3")])
case("san_registered_id", lambda: make(name("san"), san=[x509.RegisteredID(ObjectIdentifier("1.2.3.4"))]),
     san=[("registered_id", "1.2.3.4")])
case("san_many_200", lambda: make(name("san"), san=[x509.DNSName(f"h{i}.example.com") for i in range(200)]),
     san=[("dns", f"h{i}.example.com") for i in range(200)])
case("san_absent", lambda: make(name("nosan")), san=[])

# ---- basic constraints --------------------------------------------------------------------
case("bc_ca_pathlen0", lambda: make(name("ca"), bc=(True, 0)), is_ca=True, path_length=0)
case("bc_ca_pathlen3", lambda: make(name("ca"), bc=(True, 3)), is_ca=True, path_length=3)
case("bc_ca_no_pathlen", lambda: make(name("ca"), bc=(True, None)), is_ca=True, path_length=None)
case("bc_leaf_false", lambda: make(name("leaf"), bc=(False, None)), is_ca=False, path_length=None)
case("bc_absent", lambda: make(name("nobc")), is_ca=None)
