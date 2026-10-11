#!/usr/bin/env python3
"""Create a small folder of SYNTHETIC certificate files to scan in a demo:  demo_certs/

    .venv\\Scripts\\python tools\\make_demo_certs.py                 # writes demo_certs/ next to where you run it
    .venv\\Scripts\\python tools\\make_demo_certs.py --out C:\\demo   # or anywhere you choose

Only certificates are written, never a private key. The certificates are self-signed, belong to nobody, and use names ending in
`.demo.local`. They give a scan something to find with some variety: valid, expiring soon and expired certificates, RSA 2048 and
3072 and two elliptic curves, SHA-256 and SHA-384 signatures, and one certificate stored in two files (a duplicate).

Needs the `cryptography` package from requirements-dev.txt (the agent itself does not).
"""
from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

# (file name, key factory, signature hash, days since "not before", days until "not after")
SPECS = [
    ("valid-rsa2048.pem", lambda: rsa.generate_private_key(65537, 2048), hashes.SHA256, 30, 335),
    ("valid-ec-p256.pem", lambda: ec.generate_private_key(ec.SECP256R1()), hashes.SHA256, 30, 335),
    ("strong-rsa3072.pem", lambda: rsa.generate_private_key(65537, 3072), hashes.SHA384, 5, 700),
    ("valid-ec-p384.pem", lambda: ec.generate_private_key(ec.SECP384R1()), hashes.SHA384, 60, 300),
    ("expiring-soon.pem", lambda: ec.generate_private_key(ec.SECP256R1()), hashes.SHA256, 355, 10),
    ("expired.pem", lambda: rsa.generate_private_key(65537, 2048), hashes.SHA256, 800, -60),
]
DUPLICATE_OF = ("valid-rsa2048.pem", "copy-of-valid-rsa2048.pem")


def build_certificate(common_name: str, key, signature_hash, started_days_ago: int, expires_in_days: int) -> bytes:
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(days=started_days_ago)).not_valid_after(now + dt.timedelta(days=expires_in_days))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
                   .sign(key, signature_hash()))
    return certificate.public_bytes(serialization.Encoding.PEM)             # the certificate only: the key is discarded


def create(out: pathlib.Path) -> list[pathlib.Path]:
    out.mkdir(parents=True, exist_ok=True)
    written: list[pathlib.Path] = []
    for file_name, make_key, signature_hash, started, expires in SPECS:
        path = out / file_name
        path.write_bytes(build_certificate(file_name.removesuffix(".pem") + ".demo.local", make_key(), signature_hash, started, expires))
        written.append(path)
    source, copy = out / DUPLICATE_OF[0], out / DUPLICATE_OF[1]
    copy.write_bytes(source.read_bytes())
    written.append(copy)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write synthetic, certificate-only demo files to scan.")
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path("demo_certs"), help="folder to write (default: demo_certs)")
    args = parser.parse_args(argv)
    files = create(args.out)
    print(f"wrote {len(files)} certificate files (no private keys) to {args.out.resolve()}")
    for path in files:
        print(f"  {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
