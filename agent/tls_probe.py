"""One active TLS probe of one local listener, and the record it produces (stdlib only).

WHAT A RECORD IS. Each record describes ONE PROBE ATTEMPT made by this agent against a listener on this machine. It is not
a passively observed connection and not other programs' network traffic. Fixed markers say so on every record:
`warnings` always contains "active_probe" and "packet_counts_unavailable", `event_count` is 1 (one probe attempt),
`packet_count` is 0 (packet counts are unavailable: nothing is captured) and `event_counts.probe_attempts` is 1.
`direction` is always "unknown": a synthetic probe is neither inbound nor outbound traffic.

HOW IT PROBES. The probe socket is first BOUND to the destination address (port 0). The operating system only allows that
for an address assigned to this machine, so a non-local address fails before any connection is attempted. The bind also
gives the real source address and port, even if the connection is then refused. After connecting, the peer address is
checked once more. Then the handshake is made WITHOUT sending application data, WITHOUT SNI (an IP literal sends none) and
WITHOUT verifying the certificate (this is a metadata probe, no trust decision is made). The socket is closed as soon as
the facts have been read.

WHAT IS RECORDED. Version, cipher and certificate FACTS (parsed with agent.x509_parse). The certificate bytes are parsed and
dropped; they never appear in a record, a summary or a log. A failed or inconclusive handshake produces a record with a fixed
outcome and warning code and NO version, cipher or certificate: nothing is invented. Peer certificates other than the leaf
need CPython's private chain API; if it is missing or fails, the record holds the leaf only and says so (`chain_unavailable`).
"""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass

from .observations import iso_utc, safe_text
from .tls_targets import ProcessInfo, Target
from .x509_parse import CertInfo, CertParseError, parse_certificate

RECORD_FIELDS = (
    "observed_at", "direction", "transport", "src_ip", "src_port", "dst_ip", "dst_port", "handshake_outcome", "sni",
    "tls_version", "cipher_suite", "cert_visibility", "pid", "process_name", "exe_path", "process_attribution",
    "event_count", "packet_count", "event_counts", "evidence_confidence", "warnings", "peer_certificates",
)
CERT_FACT_FIELDS = ("sha256", "serial_hex", "subject", "issuer", "san", "key_algorithm", "key_size", "key_curve",
                    "signature_algorithm", "not_before", "not_after", "is_ca")
MARKER_WARNINGS = ("active_probe", "packet_counts_unavailable")
MAX_PEER_CERTIFICATES = 10
_WARNING_CODE = re.compile(r"[a-z0-9_]{1,64}")
VERSIONS = {"SSLv3": "SSL3", "TLSv1": "TLS1.0", "TLSv1.1": "TLS1.1", "TLSv1.2": "TLS1.2", "TLSv1.3": "TLS1.3"}


class ProbeAborted(Exception):
    """The probe was stopped BEFORE any handshake, and no record is produced. `code` is a fixed identifier."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Timeouts:
    connect: float = 2.0
    handshake: float = 3.0


def derive_confidence(outcome: str, peer_count: int, warnings: list[str]) -> str:
    """The one rule for evidence confidence (the backend applies the same rule and rejects a record that disagrees)."""
    if outcome != "completed" or peer_count == 0:
        return "low" if outcome != "completed" else "medium"
    extras = [w for w in warnings if w not in MARKER_WARNINGS]
    return "medium" if extras else "high"


def _cert_facts(info: CertInfo) -> dict:
    return {
        "sha256": info.sha256, "serial_hex": info.serial_hex, "subject": info.subject, "issuer": info.issuer,
        "san": [{"type": s.type, "value": s.value} for s in info.san], "key_algorithm": info.key_algorithm,
        "key_size": info.key_size, "key_curve": info.key_curve, "signature_algorithm": info.signature_algorithm,
        "not_before": iso_utc(info.not_before), "not_after": iso_utc(info.not_after), "is_ca": info.is_ca,
    }


def _address(sockname) -> tuple[str, int]:
    return str(ipaddress.ip_address(sockname[0].split("%", 1)[0])), int(sockname[1])


def _sockaddr(ip: str, port: int) -> tuple:
    return (ip, port, 0, 0) if ":" in ip else (ip, port)


def _reason_code(error: ssl.SSLError) -> str:
    """A fixed-vocabulary code for an SSL error (lower-case letters, digits, underscore), never the message."""
    reason = getattr(error, "reason", None)
    if isinstance(reason, str):
        code = "".join(c if c.isalnum() else "_" for c in reason.lower())[:64]
        if code:
            return code
    return "handshake_failed"


def _chain_der(ssock: ssl.SSLSocket, leaf: bytes) -> list[bytes] | None:
    """The peer's certificates through CPython's PRIVATE chain API, or None if it is unavailable, fails, or disagrees with
    the public leaf. Optional by design: callers fall back to the leaf alone."""
    try:
        chain = ssock._sslobj.get_unverified_chain()                      # noqa: SLF001 - private API, optional
        if not chain:
            return None
        encoded = [bytes(c.public_bytes(ssl._ssl.ENCODING_DER)) for c in chain]   # noqa: SLF001
    except Exception:                                                     # noqa: BLE001 - any failure means "no chain"
        return None
    return encoded if encoded and encoded[0] == leaf else None


def _read_certificates(ssock: ssl.SSLSocket, warnings: set[str]) -> list[dict]:
    """The peer certificate facts, leaf first. All bytes stay inside this function."""
    leaf = ssock.getpeercert(binary_form=True)
    if not leaf:
        warnings.add("certificate_unavailable")
        return []
    chain = _chain_der(ssock, leaf)
    if chain is None:
        warnings.add("chain_unavailable")
        chain = [leaf]
    if len(chain) > MAX_PEER_CERTIFICATES:
        warnings.add("chain_truncated")
        chain = chain[:MAX_PEER_CERTIFICATES]
    facts: list[dict] = []
    for position, der in enumerate(chain):
        try:
            info = parse_certificate(der)
        except CertParseError:
            warnings.add("certificate_unparsable" if position == 0 else "chain_unparsable")
            break
        facts.append(_cert_facts(info))
        if position == 0:
            warnings.update(w for w in info.warnings if _WARNING_CODE.fullmatch(w))
    return facts


def probe(target: Target, timeouts: Timeouts, *, now, attribution: tuple[str, ProcessInfo | None],
          socket_factory=socket.socket) -> dict:
    """Probe one validated target and return its record, or raise ProbeAborted (no record) if the target is not local."""
    family = socket.AF_INET6 if ":" in target.ip else socket.AF_INET
    sock = socket_factory(family, socket.SOCK_STREAM)
    wrapped = None
    try:
        sock.settimeout(timeouts.connect)
        try:
            sock.bind(_sockaddr(target.ip, 0))               # only possible for an address assigned to this machine
        except OSError:
            raise ProbeAborted("target_not_local") from None
        src_ip, src_port = _address(sock.getsockname())
        outcome, warnings = "incomplete", {"connection_failed"}
        version = cipher = None
        certificates: list[dict] = []
        try:
            sock.connect(_sockaddr(target.ip, target.port))
        except ConnectionRefusedError:
            warnings = {"connection_refused"}
        except (TimeoutError, socket.timeout):
            warnings = {"connect_timeout"}
        except OSError:
            warnings = {"connection_failed"}
        else:
            if _address(sock.getpeername())[0] != target.ip:
                raise ProbeAborted("peer_mismatch")
            warnings = set()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE               # metadata probe: no trust decision, nothing is sent
            sock.settimeout(timeouts.handshake)
            try:
                wrapped = context.wrap_socket(sock, server_hostname=None, do_handshake_on_connect=False)
                wrapped.do_handshake()
            except (TimeoutError, socket.timeout):
                outcome, warnings = "incomplete", {"handshake_timeout"}
            except ssl.SSLError as error:
                reason = _reason_code(error)
                if "alert" in reason:
                    outcome, warnings = "alert", {reason}
                else:
                    outcome, warnings = "failed", {"handshake_failed"}
            except ConnectionResetError:
                outcome, warnings = "incomplete", {"connection_reset"}
            except OSError:
                outcome, warnings = "failed", {"handshake_failed"}
            else:
                version = VERSIONS.get(wrapped.version() or "")
                suite = wrapped.cipher()
                cipher = suite[0] if suite and isinstance(suite[0], str) and 0 < len(suite[0]) <= 128 else None
                if version is None or cipher is None:
                    outcome, warnings, version, cipher = "unknown", {"unrecognised_handshake_details"}, None, None
                else:
                    outcome = "completed"
                    certificates = _read_certificates(wrapped, warnings)
    finally:
        try:
            (wrapped or sock).close()
        except OSError:
            pass

    status, info = attribution
    all_warnings = list(MARKER_WARNINGS) + sorted(warnings)
    completed = outcome == "completed"
    return {
        "observed_at": iso_utc(now()), "direction": "unknown", "transport": "tcp",
        "src_ip": src_ip, "src_port": src_port, "dst_ip": target.ip, "dst_port": target.port,
        "handshake_outcome": outcome, "sni": None, "tls_version": version, "cipher_suite": cipher,
        "cert_visibility": "visible" if certificates else "not_observed",
        "pid": target.pid, "process_name": info.name if info else None,
        "exe_path": safe_text(info.exe_path) if info else None, "process_attribution": status,
        "event_count": 1, "packet_count": 0,
        "event_counts": {"probe_attempts": 1, "handshake_completed": 1 if completed else 0},
        "evidence_confidence": derive_confidence(outcome, len(certificates), all_warnings),
        "warnings": all_warnings, "peer_certificates": certificates,
    }

