"""Test-only helpers for building PEM files and key-bearing fixtures (uses `cryptography`)."""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import certgen


def pem_encode(der: bytes, *, label: bytes = b"CERTIFICATE", width: int = 64,
               eol: bytes = b"\n", final_eol: bool = True) -> bytes:
    b64 = base64.b64encode(der)
    lines = [b64[i:i + width] for i in range(0, len(b64), width)] or [b""]
    body = eol.join([b"-----BEGIN " + label + b"-----", *lines, b"-----END " + label + b"-----"])
    return body + (eol if final_eol else b"")


def der_of(case: str) -> bytes:
    return certgen.CASES[case][0]()


# ---------------------------------------------------------------- private-key fixtures
_PASSWORD = b"canary-password"


def _keys():
    # The RSA key is deliberately NOT the one the test certificate (rsa2048) was made with: a
    # certificate embeds its key's public half, so a whole-key canary would flag public data.
    # The realistic matching-pair case is tested separately with private-only canaries.
    return {
        "rsa": certgen.key("rsa3072"),
        "ec": certgen.key("p384"),
        "ed25519": certgen.key("ed25519"),
    }


def private_components(key) -> list[bytes]:
    """Raw bytes of the PRIVATE parts of a key object (never the public parts)."""
    if isinstance(key, rsa.RSAPrivateKey):
        n = key.private_numbers()
        return [v.to_bytes((v.bit_length() + 7) // 8, "big") for v in (n.d, n.p, n.q, n.dmp1, n.dmq1, n.iqmp)]
    if isinstance(key, ec.EllipticCurvePrivateKey):
        v = key.private_numbers().private_value
        return [v.to_bytes((v.bit_length() + 7) // 8, "big")]
    return [key.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())]


def private_key_pems() -> dict[str, bytes]:
    """Every private-key PEM flavour we can think of, keyed by a descriptive name."""
    k = _keys()
    pem, fmt = ser.Encoding.PEM, ser.PrivateFormat
    out = {
        "pkcs8_rsa": k["rsa"].private_bytes(pem, fmt.PKCS8, ser.NoEncryption()),
        "traditional_rsa": k["rsa"].private_bytes(pem, fmt.TraditionalOpenSSL, ser.NoEncryption()),
        "traditional_ec": k["ec"].private_bytes(pem, fmt.TraditionalOpenSSL, ser.NoEncryption()),
        "pkcs8_ec": k["ec"].private_bytes(pem, fmt.PKCS8, ser.NoEncryption()),
        "pkcs8_ed25519": k["ed25519"].private_bytes(pem, fmt.PKCS8, ser.NoEncryption()),
        "encrypted_pkcs8_rsa": k["rsa"].private_bytes(pem, fmt.PKCS8, ser.BestAvailableEncryption(_PASSWORD)),
        # RFC 1421 style: carries Proc-Type / DEK-Info header lines inside the block
        "encrypted_traditional_rsa": k["rsa"].private_bytes(
            pem, fmt.TraditionalOpenSSL, ser.BestAvailableEncryption(_PASSWORD)),
        "openssh_ed25519": k["ed25519"].private_bytes(pem, fmt.OpenSSH, ser.NoEncryption()),
        "openssh_rsa": k["rsa"].private_bytes(pem, fmt.OpenSSH, ser.NoEncryption()),
    }
    return out


def key_body_text(key_pem: bytes) -> str:
    """The base64 payload of a PEM block as one string (headers and markers removed)."""
    lines = [ln.strip() for ln in key_pem.decode("ascii").splitlines()]
    return "".join(ln for ln in lines if ln and not ln.startswith("-----") and ":" not in ln)


def canary_windows(text: str, n: int = 32, step: int = 1) -> set[str]:
    return {text[i:i + n] for i in range(0, max(len(text) - n + 1, 1), step)}


def canary_set(key_pem: bytes, *, n: int = 32, step: int = 1) -> set[str]:
    """Substrings that must never appear in any output: base64 windows and hex-of-DER windows."""
    body = key_body_text(key_pem)
    windows = canary_windows(body, n, step)
    try:
        windows |= canary_windows(base64.b64decode(body).hex(), n, step)
    except Exception:                                   # noqa: BLE001 - fixture helper
        pass
    return windows


def leaked(haystack: str, canaries: set[str]) -> list[str]:
    return [c for c in canaries if c in haystack]
