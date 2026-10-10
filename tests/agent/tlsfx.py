"""Test fixtures for the TLS probe: local TLS / plain-text / silent servers on loopback, and throwaway certificates.

Everything lives under the test's tmp_path. The private keys are generated per test, are never read by the code under
test, and exist only so that a local test server can complete a handshake.
"""
from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

NOW = dt.datetime.now(dt.timezone.utc)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _sign(subject, issuer_name, public_key, signer, *, ca: bool, sans=()):
    builder = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(issuer_name).public_key(public_key)
               .serial_number(x509.random_serial_number()).not_valid_before(NOW - dt.timedelta(days=1))
               .not_valid_after(NOW + dt.timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return builder.sign(signer, hashes.SHA256())


@dataclass(frozen=True)
class Material:
    cert_file: Path                 # the chain the server presents, leaf first
    key_file: Path
    ders: tuple[bytes, ...]         # DER of each presented certificate, leaf first (for assertions only)
    key_pem: bytes                  # the throwaway private key (a canary: it must never appear in any record)

    @property
    def leaf_sha256(self) -> str:
        import hashlib
        return hashlib.sha256(self.ders[0]).hexdigest()


def make_material(tmp_path: Path, *, chain: bool = False, name: str = "probe-test.local") -> Material:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if chain:
        root = _sign("Test Root", _name("Test Root"), root_key.public_key(), root_key, ca=True)
        inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer = _sign("Test Intermediate", root.subject, inter_key.public_key(), root_key, ca=True)
        leaf = _sign(name, issuer.subject, leaf_key.public_key(), inter_key, ca=False, sans=(name,))
        certs = [leaf, issuer, root]
    else:
        leaf = _sign(name, _name(name), leaf_key.public_key(), leaf_key, ca=False, sans=(name,))
        certs = [leaf]
    cert_file, key_file = tmp_path / "server-chain.pem", tmp_path / "server-key.pem"
    cert_file.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs))
    key_pem = leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    key_file.write_bytes(key_pem)
    return Material(cert_file, key_file, tuple(c.public_bytes(serialization.Encoding.DER) for c in certs), key_pem)


class _Server:
    """A listener on 127.0.0.1 (ephemeral port) served by a background thread. Records what the client sent."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.received = b""
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        self.sock.settimeout(0.1)
        while not self._stop.is_set():
            try:
                client, _ = self.sock.accept()
            except OSError:
                continue
            self.connections += 1
            try:
                self.handle(client)
            except (OSError, ssl.SSLError):
                pass
            finally:
                try:
                    client.close()
                except OSError:
                    pass

    def handle(self, client):
        raise NotImplementedError

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class TlsServer(_Server):
    def __init__(self, material: Material, *, max_version=None, min_version=None):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(material.cert_file, material.key_file)
        if max_version is not None:
            self.context.maximum_version = max_version
        if min_version is not None:
            self.context.minimum_version = min_version
        super().__init__()

    def handle(self, client):
        with self.context.wrap_socket(client, server_side=True) as tls:
            tls.settimeout(1.0)
            try:
                self.received += tls.recv(4096)          # a probe sends nothing, so this ends with the client closing
            except (OSError, ssl.SSLError):
                pass


class PlainServer(_Server):
    """Speaks plain text, not TLS."""

    def handle(self, client):
        client.settimeout(0.5)
        try:
            client.sendall(b"HTTP/1.0 200 OK\r\n\r\nhello")
            self.received += client.recv(4096)
        except OSError:
            pass


class SilentServer(_Server):
    """Accepts the connection and never answers."""

    def handle(self, client):
        self._stop.wait(1.5)


def closed_port() -> int:
    """A loopback port nothing listens on."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def tls_versions():
    """The (name, ssl.TLSVersion) pairs this Python/OpenSSL can serve."""
    out = [("TLS1.2", ssl.TLSVersion.TLSv1_2)]
    if getattr(ssl, "HAS_TLSv1_3", False):
        out.append(("TLS1.3", ssl.TLSVersion.TLSv1_3))
    return out
