"""Test-only PKCS#12 fixture builders (no OpenSSL; `cryptography`, hand-built DER, and .NET via PowerShell).

Three kinds of fixture:
  * `cryptography`-made files (plain containers, or password-protected);
  * Windows-native files exported by .NET itself (the realistic empty-password, encrypted-certificate flavour);
  * hand-built STRUCTURES whose key bags contain deliberately invalid bytes, so any code that tried to
    decode or parse a key bag would visibly fail, and whose "ciphertext" is fake (structure is all that
    matters for inspection).
Everything uses throwaway test keys.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.serialization import pkcs12

import certgen
from agent.der import children, decode_oid, read_tlv
from certgen import _enc

# object identifiers (hex of the DER content bytes)
OID_DATA = "2a864886f70d010701"
OID_SIGNED_DATA = "2a864886f70d010702"
OID_ENVELOPED_DATA = "2a864886f70d010703"
OID_ENCRYPTED_DATA = "2a864886f70d010706"
OID_CERT_BAG = "2a864886f70d010c0a0103"
OID_KEY_BAG = "2a864886f70d010c0a0101"
OID_SHROUDED_KEY_BAG = "2a864886f70d010c0a0102"
OID_SECRET_BAG = "2a864886f70d010c0a0105"
OID_X509_CERT = "2a864886f70d01091601"
OID_PBE_3DES = "2a864886f70d010c0103"
OID_PBES2 = "2a864886f70d01050d"
OID_UNKNOWN = "2a030405"


def oid(hexstr: str) -> bytes:
    return _enc(0x06, bytes.fromhex(hexstr))


@functools.lru_cache(maxsize=None)
def chain() -> tuple[bytes, bytes, bytes]:
    """(root, intermediate, leaf) DER; the leaf's key is certgen.key('rsa2048')."""
    root = certgen.make(certgen.name("Root"), "p256", bc=(True, None))
    inter = certgen.make(certgen.name("Inter"), "p384", sign_kind="p256", issuer=certgen.name("Root"), bc=(True, 0))
    leaf = certgen.make(certgen.name("leaf"), "rsa2048", sign_kind="p384", issuer=certgen.name("Inter"))
    return root, inter, leaf


def fp(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _cert(der: bytes):
    return x509.load_der_x509_certificate(der)


LEAF_KEY = lambda: certgen.key("rsa2048")           # noqa: E731 - the private key that matches chain()[2]


# ---------------------------------------------------------------- cryptography-made files
def plain_with_key(extra_ca: tuple[bytes, ...] | None = None) -> bytes:
    """Unprotected PFX: certificates AND the private key sit in plain `data` containers."""
    root, inter, leaf = chain()
    cas = [_cert(d) for d in (extra_ca if extra_ca is not None else (inter, root))]
    return pkcs12.serialize_key_and_certificates(b"fixture", LEAF_KEY(), _cert(leaf), cas, ser.NoEncryption())


def plain_certs_only(ders: tuple[bytes, ...]) -> bytes:
    return pkcs12.serialize_key_and_certificates(b"fixture", None, None, [_cert(d) for d in ders], ser.NoEncryption())


def protected(password: bytes = b"secret", legacy: bool = False) -> bytes:
    """Password-protected PFX: certificates in an encryptedData container, key shrouded in a data container."""
    root, inter, leaf = chain()
    if legacy:
        enc = (ser.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(2000)
               .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1()).build(password))
    else:
        enc = ser.BestAvailableEncryption(password)
    return pkcs12.serialize_key_and_certificates(b"fixture", LEAF_KEY(), _cert(leaf), [_cert(inter), _cert(root)], enc)


def private_key_der() -> bytes:
    return LEAF_KEY().private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())


# ---------------------------------------------------------------- Windows-native files (exported by .NET)
class FixtureUnavailable(Exception):
    pass


_EXPORT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$in = [Console]::In.ReadToEnd() | ConvertFrom-Json
Add-Type -AssemblyName System.Security
$X = 'System.Security.Cryptography.X509Certificates'
$col = New-Object "$X.X509Certificate2Collection"
if ($in.mode -ne 'certs_only') { $col.Import([Convert]::FromBase64String($in.pfx), $null, [Enum]::Parse("$X.X509KeyStorageFlags", 'Exportable')) }
foreach ($d in $in.extras) { $col.Add((New-Object "$X.X509Certificate2" (, [Convert]::FromBase64String($d)))) | Out-Null }
$password = $null
if ($in.mode -eq 'protected') { $password = 'secret' }
[Convert]::ToBase64String($col.Export([Enum]::Parse("$X.X509ContentType", 'Pfx'), $password))
"""


@functools.lru_cache(maxsize=None)
def windows_native(mode: str) -> bytes:
    """mode: 'chain' (leaf+key+inter+root, empty password), 'certs_only' (inter+root), 'single' (inter only),
    'protected' (the chain, password 'secret')."""
    if os.name != "nt":
        raise FixtureUnavailable("needs Windows")
    root, inter, leaf = chain()
    extras = {"single": (inter,), "duplicate": (inter, inter, root)}.get(mode, (inter, root))
    request = {"mode": "certs_only" if mode in ("single", "duplicate") else mode,
               "pfx": base64.b64encode(plain_with_key(extra_ca=())).decode(),
               "extras": [base64.b64encode(d).decode() for d in extras]}
    argv = [os.path.join(os.environ["SystemRoot"], "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
            "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
            base64.b64encode(_EXPORT_SCRIPT.encode("utf-16-le")).decode()]
    try:
        done = subprocess.run(argv, input=json.dumps(request).encode(), capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise FixtureUnavailable(type(e).__name__) from None
    if done.returncode != 0:
        raise FixtureUnavailable(f"fixture export failed rc={done.returncode}")
    return base64.b64decode(done.stdout.strip())


# ---------------------------------------------------------------- hand-built structures (fake ciphertext)
def cert_bag(der: bytes) -> bytes:
    value = _enc(0x30, oid(OID_X509_CERT) + _enc(0xA0, _enc(0x04, der)))
    return _enc(0x30, oid(OID_CERT_BAG) + _enc(0xA0, value))


def key_bag(canary: bytes, shrouded: bool = True) -> bytes:
    """A key bag whose value is a SEQUENCE of garbage: valid headers, invalid inside. Decoding it must fail."""
    kind = OID_SHROUDED_KEY_BAG if shrouded else OID_KEY_BAG
    return _enc(0x30, oid(kind) + _enc(0xA0, _enc(0x30, canary)))


def other_bag(oid_hex: str, payload: bytes) -> bytes:
    return _enc(0x30, oid(oid_hex) + _enc(0xA0, _enc(0x30, payload)))


def data_container(bags: list[bytes]) -> bytes:
    return _enc(0x30, oid(OID_DATA) + _enc(0xA0, _enc(0x04, _enc(0x30, b"".join(bags)))))


def encrypted_container(*, algorithm: str = OID_PBE_3DES, content_type: str = OID_DATA,
                        ciphertext: bytes = b"\x42" * 64) -> bytes:
    algorithm_id = _enc(0x30, oid(algorithm) + _enc(0x30, _enc(0x04, b"salt1234") + _enc(0x02, b"\x08\x00")))
    content = _enc(0x30, oid(content_type) + algorithm_id + _enc(0x80, ciphertext))
    return _enc(0x30, oid(OID_ENCRYPTED_DATA) + _enc(0xA0, _enc(0x30, _enc(0x02, b"\x00") + content)))


def structural_pfx(containers: list[bytes], *, authsafe_type: str = OID_DATA, mac: bool = True, version: int = 3) -> bytes:
    authenticated_safe = _enc(0x30, b"".join(containers))
    content_info = _enc(0x30, oid(authsafe_type) + _enc(0xA0, _enc(0x04, authenticated_safe)))
    body = _enc(0x02, bytes([version])) + content_info
    if mac:
        body += _enc(0x30, _enc(0x30, oid("2b0e03021a") + b"\x05\x00") + _enc(0x04, b"\x11" * 20) + _enc(0x04, b"\x22" * 8))
    return _enc(0x30, body)


def containers_of(pfx: bytes) -> list[bytes]:
    """Independent re-parse (test-owned): the raw ContentInfo elements inside a PFX's AuthenticatedSafe."""
    top = children(read_tlv(pfx, 0))
    wrapper = children(children(top[1])[1])[0]
    return [pfx[c.head:c.end] for c in children(read_tlv(pfx, wrapper.start, wrapper.end))]


def container_types(pfx: bytes) -> list[str]:
    return [decode_oid(children(read_tlv(c, 0))[0].value) for c in containers_of(pfx)]


def has_mac(pfx: bytes) -> bool:
    return len(children(read_tlv(pfx, 0))) == 3


def shrouded_key_values(pfx: bytes) -> list[bytes]:
    """Independent (test-owned) locator: the raw VALUE bytes of every key bag in plain `data` containers.

    Used only to build canaries; the code under test never does this.
    """
    out = []
    for container in containers_of(pfx):
        parts = children(read_tlv(container, 0))
        if decode_oid(parts[0].value) != "1.2.840.113549.1.7.1":
            continue
        octet = children(parts[1])[0]
        safe = read_tlv(container, octet.start, octet.end)
        for bag in children(safe):
            fields = children(bag)
            if decode_oid(fields[0].value) in ("1.2.840.113549.1.12.10.1.1", "1.2.840.113549.1.12.10.1.2"):
                out.append(container[fields[1].start:fields[1].end])
    return out
