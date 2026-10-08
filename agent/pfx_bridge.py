"""PKCS#12 (.pfx/.p12) certificate discovery on Windows, without ever handing a private key to the OS.

How it works (Option B):

  1. Python walks the PKCS#12 structure with the stdlib DER reader (agent/der.py).
  2. Certificate bags inside plain `data` containers are read directly: no OS call, any platform.
  3. Key bags (keyBag, pkcs8ShroudedKeyBag) and every other bag type are SKIPPED WITHOUT BEING DECODED:
     only the bag-type OID is read; the bag value is never sliced, parsed, copied or reported.
  4. Only `encryptedData` containers (where standard producers keep the certificates) can hold
     certificates that need the OS to decrypt them. Those ContentInfo elements are copied, byte for
     byte, into a NEW minimal PFX that contains nothing else (no key container, no MAC) and sent to a
     constant PowerShell script over stdin. The script imports it with an ephemeral key set and returns
     each certificate's public DER as JSON. No file, path, password or secret is ever put in argv.
  5. Every returned certificate goes through the existing Phase 1a parser; the JSON is untrusted.

No password is ever supplied (the import uses "no password") and none is guessed.

KNOWN LIMITATION - read this: Python cannot see inside an `encryptedData` container. A non-standard
PKCS#12 that stores a PRIVATE KEY inside an encryptedData container would be decrypted by Windows
inside the short-lived PowerShell process (ephemeral, never persisted, never read or returned by us).
Standard producers (Windows, OpenSSL, Java, .NET, `cryptography`) keep keys in a separate `data`
container, which this module withholds. The module refuses (unsupported) any layout it cannot reason
about: public-key integrity mode, unknown container types, unknown encryption algorithms. It does NOT
claim to be able to prove that an encrypted container is certificate-only.

Other limits: PFX files using BER indefinite lengths are not recognised (the DER reader rejects them);
the OS returns certificates in its own order, so no chain position is inferred from PFX order.

INTEGRITY OF OS-DECRYPTED CERTIFICATES IS NOT VERIFIED. Be precise about what is and is not claimed:

  * The ORIGINAL PFX/P12 file may well carry MAC/integrity protection (macData). This module never
    verifies it: doing so would mean hashing the key container, which is deliberately never processed.
  * The temporary, key-free PFX that is built for PowerShell intentionally has NO MAC. A MAC covers the
    whole AuthenticatedSafe, including the withheld key container, so it could not be carried over.
  * Therefore a corrupted `encryptedData` container can decrypt to altered-but-parseable certificates
    instead of failing (measured: roughly half of single-byte corruptions inside the ciphertext), and
    certificate evidence that came back through that path CANNOT claim original-container integrity.

So every certificate obtained from an `encryptedData` container through the PowerShell bridge carries the
warning `pkcs12_integrity_not_verified`, which caps its evidence confidence at "medium". Certificates are
NOT rejected for this reason: if they parse, they are reported. Certificates read directly from plain
`data` containers never pass through that path and are not affected. The warning is a fixed string and
never contains file, key or password material.
"""
from __future__ import annotations

import base64
import binascii
import dataclasses
import json
import os
import re
import subprocess
from dataclasses import dataclass

from .cert_file import CertEntry, FileParse, _entry_from_der, _file_status, _result
from .der import INTEGER, OCTET_STRING, OID, SEQUENCE, DerError, children, decode_integer, decode_oid, read_tlv
from .x509_parse import MAX_CERT_BYTES

DEFAULT_TIMEOUT_SECONDS = 30
MAX_CONTAINERS = 64
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_RETURNED_CERTS = 10_000

_OID_DATA = "1.2.840.113549.1.7.1"
_OID_ENCRYPTED_DATA = "1.2.840.113549.1.7.6"
_OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3"
_OID_X509_CERTIFICATE = "1.2.840.113549.1.9.22.1"
# Password-based encryption schemes standard PKCS#12 producers use for certificate containers.
# Anything else is refused rather than guessed at.
_ALLOWED_ENCRYPTION = frozenset({
    "1.2.840.113549.1.12.1.2", "1.2.840.113549.1.12.1.3", "1.2.840.113549.1.12.1.4",
    "1.2.840.113549.1.12.1.5", "1.2.840.113549.1.12.1.6",            # PKCS#12 PBE (RC4-40, 3DES, RC2)
    "1.2.840.113549.1.5.13",                                         # PBES2 (AES etc.)
})

# Fixed status/detail pairs (the approved mapping)
_PASSWORD_PROTECTED = ("unsupported", "pkcs12_password_protected")
_MALFORMED = ("malformed", "pkcs12_malformed")
_NO_CERTS = ("no_certificate", "pkcs12_no_certificates")
_NO_POWERSHELL = ("unsupported", "powershell_unavailable")
_NO_PLATFORM = ("unsupported", "pkcs12_platform_unsupported")
_BRIDGE_FAILED = ("read_error", "powershell_failed")
_BRIDGE_TIMEOUT = ("read_error", "powershell_timeout")

_HRESULT_PASSWORD = frozenset({"0x80070056", "0x80090020"})          # invalid password / decrypt failure
_HRESULT_MALFORMED = frozenset({"0x80092009", "0x8009310B", "0x80093102"})   # not found / ASN.1 errors
_HRESULT_RE = re.compile(r"0x[0-9A-F]{8}\Z")

# Constant script: no interpolation, nothing from the file or the environment is ever spliced into it.
_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $text = [Console]::In.ReadToEnd().Trim()
    $bytes = [Convert]::FromBase64String($text)
    Add-Type -AssemblyName System.Security
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $col.Import($bytes, $null, $flags)
    $certs = @($col | ForEach-Object { [Convert]::ToBase64String($_.RawData) })
    ConvertTo-Json -InputObject ([ordered]@{ status = 'ok'; certs = $certs }) -Compress
} catch {
    $e = $_.Exception
    while ($e.InnerException) { $e = $e.InnerException }
    ConvertTo-Json -InputObject ([ordered]@{ status = 'error'; hresult = ('0x{0:X8}' -f $e.HResult) }) -Compress
    exit 3
}
"""
_ENCODED_SCRIPT = base64.b64encode(_SCRIPT.encode("utf-16-le")).decode("ascii")


class _Reject(Exception):
    """Internal: stop with a fixed (status, detail). Never carries file content."""

    def __init__(self, outcome: tuple[str, str]):
        super().__init__(outcome[1])
        self.status, self.detail = outcome


@dataclass(frozen=True)
class _Plan:
    plain_certs: tuple[bytes, ...]      # public certificate DER read directly, in file order
    encrypted: tuple[bytes, ...]        # raw ContentInfo bytes of allowlisted encryptedData containers


# ================================================================ 1. structure walk (no key bag is ever decoded)
def _inspect(data: bytes, limit: int) -> _Plan:
    pfx = read_tlv(data, 0)
    if pfx.tag != SEQUENCE:
        raise _Reject(_MALFORMED)
    top = children(pfx)
    if len(top) not in (2, 3) or top[0].tag != INTEGER or decode_integer(top[0].value) != 3 \
            or top[1].tag != SEQUENCE:
        raise _Reject(_MALFORMED)

    auth_info = children(top[1])
    if len(auth_info) != 2 or auth_info[0].tag != OID or auth_info[1].tag != 0xA0:
        raise _Reject(_MALFORMED)
    if decode_oid(auth_info[0].value) != _OID_DATA:
        raise _Reject(_PASSWORD_PROTECTED)          # public-key integrity mode etc.: cannot reason about it
    wrapper = children(auth_info[1])
    if len(wrapper) != 1 or wrapper[0].tag != OCTET_STRING:
        raise _Reject(_MALFORMED)
    authenticated_safe = read_tlv(data, wrapper[0].start, wrapper[0].end)   # in place: no copy of the container
    if authenticated_safe.tag != SEQUENCE:
        raise _Reject(_MALFORMED)

    containers = children(authenticated_safe)
    if len(containers) > MAX_CONTAINERS:
        raise _Reject(_MALFORMED)
    plain: list[bytes] = []
    encrypted: list[bytes] = []
    for container in containers:
        if container.tag != SEQUENCE:
            raise _Reject(_MALFORMED)
        parts = children(container)
        if len(parts) != 2 or parts[0].tag != OID or parts[1].tag != 0xA0:
            raise _Reject(_MALFORMED)
        kind = decode_oid(parts[0].value)
        if kind == _OID_DATA:
            _collect_plain_certificates(data, parts[1], plain, limit)
        elif kind == _OID_ENCRYPTED_DATA:
            _check_encrypted_container(parts[1])
            encrypted.append(data[container.head:container.end])      # a copy of THIS container only
        else:
            raise _Reject(_PASSWORD_PROTECTED)      # unknown container type: refuse rather than guess
    return _Plan(tuple(plain), tuple(encrypted))


def _collect_plain_certificates(data: bytes, explicit, out: list[bytes], limit: int) -> None:
    """Append public certificates found in a plain `data` container. Key and other bags are skipped
    by their type OID alone; their values are never touched."""
    inner = children(explicit)
    if len(inner) != 1 or inner[0].tag != OCTET_STRING:
        raise _Reject(_MALFORMED)
    safe_contents = read_tlv(data, inner[0].start, inner[0].end)         # in place: no copy
    if safe_contents.tag != SEQUENCE:
        raise _Reject(_MALFORMED)
    for bag in children(safe_contents):
        if bag.tag != SEQUENCE:
            raise _Reject(_MALFORMED)
        fields = children(bag)                                            # headers only
        if len(fields) < 2 or fields[0].tag != OID:
            raise _Reject(_MALFORMED)
        if decode_oid(fields[0].value) != _OID_CERT_BAG:
            continue                                                      # keyBag, shrouded key, ...: skipped undecoded
        if fields[1].tag != 0xA0:
            raise _Reject(_MALFORMED)
        cert_bag = children(fields[1])
        if len(cert_bag) != 1 or cert_bag[0].tag != SEQUENCE:
            raise _Reject(_MALFORMED)
        cert_fields = children(cert_bag[0])
        if len(cert_fields) != 2 or cert_fields[0].tag != OID or cert_fields[1].tag != 0xA0:
            raise _Reject(_MALFORMED)
        if decode_oid(cert_fields[0].value) != _OID_X509_CERTIFICATE:
            continue                                                      # e.g. SDSI certificates: not X.509
        value = children(cert_fields[1])
        if len(value) != 1 or value[0].tag != OCTET_STRING:
            raise _Reject(_MALFORMED)
        if len(out) <= limit:
            out.append(data[value[0].start:value[0].end])                 # a public certificate


def _check_encrypted_container(explicit) -> None:
    """Refuse (rather than guess) unless this is a standard password-encrypted `data` payload."""
    envelope = children(explicit)
    if len(envelope) != 1 or envelope[0].tag != SEQUENCE:
        raise _Reject(_MALFORMED)
    fields = children(envelope[0])                                        # EncryptedData { version, EncryptedContentInfo }
    if len(fields) != 2 or fields[0].tag != INTEGER or fields[1].tag != SEQUENCE:
        raise _Reject(_MALFORMED)
    content_info = children(fields[1])                                    # { contentType, algorithm, [0] encryptedContent }
    if len(content_info) < 2 or content_info[0].tag != OID or content_info[1].tag != SEQUENCE:
        raise _Reject(_MALFORMED)
    if decode_oid(content_info[0].value) != _OID_DATA:
        raise _Reject(_PASSWORD_PROTECTED)
    algorithm = children(content_info[1])
    if not algorithm or algorithm[0].tag != OID:
        raise _Reject(_MALFORMED)
    if decode_oid(algorithm[0].value) not in _ALLOWED_ENCRYPTION:
        raise _Reject(_PASSWORD_PROTECTED)                                # unknown scheme: fail safe


# ================================================================ 2. the key-free payload
def _tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def build_keyfree_pfx(encrypted_infos: tuple[bytes, ...]) -> bytes:
    """A new minimal PFX holding ONLY the given encryptedData ContentInfo elements.

    It intentionally has no MAC: the original MAC (if any) covers the key container, which is withheld.
    See the module docstring for what that means for the integrity of the certificates that come back.
    """
    authenticated_safe = _tlv(0x30, b"".join(encrypted_infos))
    content_info = _tlv(0x30, _tlv(0x06, bytes.fromhex("2a864886f70d010701"))
                        + _tlv(0xA0, _tlv(0x04, authenticated_safe)))
    return _tlv(0x30, _tlv(0x02, b"\x03") + content_info)


def _assert_only_encrypted_containers(payload: bytes, expected: tuple[bytes, ...]) -> None:
    """Defensive self-check: what is about to be sent contains exactly the intended containers."""
    top = children(read_tlv(payload, 0))
    wrapper = children(children(top[1])[1])[0]
    infos = children(read_tlv(payload, wrapper.start, wrapper.end))
    got = tuple(payload[i.head:i.end] for i in infos)
    if len(top) != 2 or got != expected or any(
            decode_oid(children(i)[0].value) != _OID_ENCRYPTED_DATA for i in infos):
        raise RuntimeError("refusing to send: payload is not exactly the selected encryptedData containers")


# ================================================================ 3. the PowerShell boundary
def _is_windows() -> bool:
    return os.name == "nt"


def _powershell_path() -> str | None:
    """Fixed system location (never a PATH search, so a planted powershell.exe is never used)."""
    root = os.environ.get("SystemRoot")
    if not root:
        return None
    path = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return path if os.path.isfile(path) else None


def _run_powershell(payload_b64: bytes, timeout: float) -> subprocess.CompletedProcess:
    """The ONLY place a process is started. argv is constant; the payload travels over stdin."""
    exe = _powershell_path()
    if exe is None:
        raise FileNotFoundError("powershell.exe")
    argv = [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", _ENCODED_SCRIPT]
    env = {k: os.environ[k] for k in ("SystemRoot", "windir", "SystemDrive", "TEMP", "TMP", "USERPROFILE",
                                       "APPDATA", "LOCALAPPDATA", "ProgramData", "ProgramFiles", "PATHEXT")
           if k in os.environ}
    env["PATH"] = os.path.join(os.environ.get("SystemRoot", ""), "System32")
    return subprocess.run(argv, input=payload_b64, capture_output=True, timeout=timeout, shell=False,
                          check=False, env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


class _Protocol(Exception):
    """PowerShell's output did not follow the protocol."""


def _parse_output(stdout: bytes) -> tuple[str, object]:
    """Strictly validate PowerShell's JSON. -> ('ok', [der...]) or ('error', hresult). Output is untrusted."""
    if len(stdout) > MAX_OUTPUT_BYTES:
        raise _Protocol("output too large")
    try:
        message = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _Protocol("not JSON") from None
    if not isinstance(message, dict):
        raise _Protocol("not an object")
    if set(message) == {"status", "hresult"} and message["status"] == "error":
        hresult = message["hresult"]
        if not isinstance(hresult, str) or not _HRESULT_RE.match(hresult):
            raise _Protocol("bad hresult")
        return "error", hresult
    if set(message) == {"status", "certs"} and message["status"] == "ok":
        certs = message["certs"]
        if not isinstance(certs, list) or len(certs) > MAX_RETURNED_CERTS:
            raise _Protocol("bad certificate list")
        out = []
        for item in certs:
            if not isinstance(item, str):
                raise _Protocol("certificate is not a string")
            try:
                der = base64.b64decode(item, validate=True)
            except (binascii.Error, ValueError):
                raise _Protocol("invalid base64") from None
            if not der or len(der) > MAX_CERT_BYTES:
                raise _Protocol("certificate size out of range")
            out.append(der)
        return "ok", out
    raise _Protocol("unexpected fields")


def _decrypt_certificates(encrypted: tuple[bytes, ...], timeout: float) -> tuple[list[bytes], tuple[str, str] | None]:
    """-> (public DER certificates, failure). Exactly one of them is meaningful."""
    if not _is_windows():
        return [], _NO_PLATFORM
    if _powershell_path() is None:
        return [], _NO_POWERSHELL
    payload = build_keyfree_pfx(encrypted)
    _assert_only_encrypted_containers(payload, encrypted)
    try:
        proc = _run_powershell(base64.b64encode(payload), timeout)
    except subprocess.TimeoutExpired:
        return [], _BRIDGE_TIMEOUT
    except FileNotFoundError:
        return [], _NO_POWERSHELL
    except OSError:
        return [], _BRIDGE_FAILED
    try:
        kind, value = _parse_output(proc.stdout)
    except _Protocol:
        return [], _BRIDGE_FAILED
    if kind == "ok":
        return value, None
    if value in _HRESULT_PASSWORD:
        return [], _PASSWORD_PROTECTED
    if value in _HRESULT_MALFORMED:
        return [], _MALFORMED
    return [], _BRIDGE_FAILED


# ================================================================ 4. public entry point
INTEGRITY_WARNING = "pkcs12_integrity_not_verified"


def _unverified(entry: CertEntry) -> CertEntry:
    """Mark a certificate that came back from the PowerShell bridge (decrypted without a MAC).

    Called ONLY for certificates returned by the OS for an `encryptedData` container. A failed entry
    (no certificate) is returned unchanged: there is no evidence to qualify.
    """
    if entry.cert is None:
        return entry
    cert = dataclasses.replace(entry.cert, warnings=entry.cert.warnings + (INTEGRITY_WARNING,))
    return CertEntry(entry.index, entry.parse_status, entry.detail, cert)


def _failure(outcome: tuple[str, str]) -> FileParse:
    return _result("pkcs12", outcome[0], outcome[1])


def read_pkcs12(data: bytes, *, max_certs: int, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> FileParse:
    """Public certificates of a PKCS#12 file. Never raises for bad content; never returns key material."""
    try:
        plan = _inspect(bytes(data), max_certs)
    except _Reject as rejected:
        return _failure((rejected.status, rejected.detail))
    except (DerError, IndexError):
        return _failure(_MALFORMED)

    # Chain position is NOT inferred from PFX order: entries only carry an ordinal for bookkeeping, and
    # observations.records_from_file_parse reports chain_index as null for PKCS#12.
    # Provenance is tracked explicitly: `plain_ders` were read straight from plain containers; `os_ders` are
    # the only certificates that ever came back through the PowerShell bridge.
    plain_ders = list(plan.plain_certs[:max_certs])
    os_ders: list[bytes] = []
    truncated = len(plan.plain_certs) > max_certs
    failure = None
    if plan.encrypted:
        room = max_certs - len(plain_ders)
        if room <= 0:
            truncated = True                                  # encrypted containers exist but are not examined
        else:
            decrypted, failure = _decrypt_certificates(plan.encrypted, timeout)
            if failure is None:
                if len(decrypted) > room:
                    truncated = True
                os_ders = decrypted[:room]

    entries = [_entry_from_der(i, der) for i, der in enumerate(plain_ders)]
    entries += [_unverified(_entry_from_der(len(plain_ders) + j, der)) for j, der in enumerate(os_ders)]
    if failure is not None:
        if not entries:
            return _failure(failure)
        entries.append(CertEntry(len(entries), failure[0], failure[1], None))     # visible, not silent
    if not entries:
        return _failure(_NO_CERTS)
    return FileParse("pkcs12", _file_status(entries), "bundle_truncated" if truncated else None,
                     tuple(entries), len(entries), truncated, False)
