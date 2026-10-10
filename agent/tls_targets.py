"""Which local TCP listeners may be probed for TLS, and who owns them (stdlib only).

Targets come ONLY from the operating system's own table of listening sockets on this machine. A caller can never add a
target: a port list in the configuration can only narrow what the OS reported. Every destination is chosen and validated
here before anything connects:

  * a wildcard listener (0.0.0.0, ::) is probed through an explicit loopback address (127.0.0.1, ::1); the wildcard address
    itself is never a destination;
  * a listener bound to a specific address is probed at that address;
  * a destination must be a literal IP address (no host names), not scoped, not IPv4-mapped, and not unspecified,
    multicast, link-local or reserved. A destination that fails this is skipped and counted, never replaced by another.

The last proof that a destination is local is made by the probe itself (agent/tls_probe.py): it binds its socket to the
destination address first, which the operating system only allows for an address assigned to this machine.

Enumeration and process lookup go through small functions that tests replace, so no test touches real services.
"""
from __future__ import annotations

import ctypes
import ipaddress
import os
import socket
from ctypes import wintypes
from dataclasses import dataclass

LOOPBACK = {4: "127.0.0.1", 6: "::1"}
MAX_PATH_CHARS = 32768


class TargetRejected(ValueError):
    """The address is not allowed as a probe destination. `code` is a fixed identifier (never the address)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class EnumerationError(RuntimeError):
    """The OS listener table could not be read. `code` is a fixed identifier."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Listener:
    ip: str            # the address the socket is bound to, as the OS reports it (may be a wildcard)
    port: int
    pid: int | None


@dataclass(frozen=True)
class Target:
    ip: str            # validated destination
    port: int
    pid: int | None    # owner of the listener, when exactly one owner is known
    ambiguous_owner: bool = False


@dataclass(frozen=True)
class ProcessInfo:
    name: str
    exe_path: str


@dataclass(frozen=True)
class TargetPlan:
    targets: tuple[Target, ...]      # eligible, deduplicated, deterministic order, at most max_targets
    listeners_found: int             # rows in the OS table (before any filtering)
    policy_skipped: int              # listeners whose destination the policy refused
    port_filtered: int               # listeners left out because the configured port list does not include them
    truncated: bool                  # eligible targets were dropped because of max_targets


# ------------------------------------------------------------------ the policy
def validate_destination(text: object) -> str:
    """The normalised literal IP address, or TargetRejected. Never resolves a name and never connects."""
    if not isinstance(text, str) or not text:
        raise TargetRejected("not_an_ip_address")
    if "%" in text:
        raise TargetRejected("scoped_address")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise TargetRejected("not_an_ip_address") from None
    if address.version == 6 and address.ipv4_mapped is not None:
        raise TargetRejected("ipv4_mapped_address")
    if address.is_unspecified:
        raise TargetRejected("unspecified_address")
    if address.is_multicast:
        raise TargetRejected("multicast_address")
    if address.is_link_local:
        raise TargetRejected("link_local_address")
    if address.is_reserved and not address.is_loopback:        # Python files ::1 under the reserved ::/8 block
        raise TargetRejected("reserved_address")
    return str(address)


def destination_for(listener: Listener) -> str:
    """The address to probe for this listener. A wildcard becomes an explicit loopback address; nothing else is substituted."""
    try:
        address = ipaddress.ip_address(listener.ip.split("%", 1)[0])
    except ValueError:
        raise TargetRejected("not_an_ip_address") from None
    if address.is_unspecified:
        return validate_destination(LOOPBACK[address.version])
    return validate_destination(listener.ip)


def build_plan(listeners: list[Listener], *, max_targets: int, ports: frozenset[int] | None = None) -> TargetPlan:
    """Turn the OS listener table into the targets to probe. `ports` can only narrow the table."""
    owners: dict[tuple[str, int], set[int | None]] = {}
    policy_skipped = port_filtered = 0
    for listener in listeners:
        if ports is not None and listener.port not in ports:
            port_filtered += 1
            continue
        if not (isinstance(listener.port, int) and 0 < listener.port <= 65535):
            policy_skipped += 1
            continue
        try:
            destination = destination_for(listener)
        except TargetRejected:
            policy_skipped += 1
            continue
        owners.setdefault((destination, listener.port), set()).add(listener.pid)
    ordered = sorted(owners, key=lambda key: (key[1], key[0]))
    chosen = []
    for key in ordered[:max_targets]:
        pids = owners[key]
        known = {pid for pid in pids if pid is not None}
        if len(known) == 1:
            chosen.append(Target(key[0], key[1], next(iter(known))))
        else:
            chosen.append(Target(key[0], key[1], None, ambiguous_owner=len(known) > 1))
    return TargetPlan(tuple(chosen), len(listeners), policy_skipped, port_filtered, len(ordered) > max_targets)


# ------------------------------------------------------------------ operating-system access (Windows)
_AF_INET, _AF_INET6 = 2, 23
_TCP_TABLE_OWNER_PID_LISTENER = 3
_ERROR_INSUFFICIENT_BUFFER = 122
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class _Row4(ctypes.Structure):
    _fields_ = [("state", wintypes.DWORD), ("local_addr", wintypes.DWORD), ("local_port", wintypes.DWORD),
                ("remote_addr", wintypes.DWORD), ("remote_port", wintypes.DWORD), ("pid", wintypes.DWORD)]


class _Row6(ctypes.Structure):
    _fields_ = [("local_addr", ctypes.c_ubyte * 16), ("local_scope", wintypes.DWORD), ("local_port", wintypes.DWORD),
                ("remote_addr", ctypes.c_ubyte * 16), ("remote_scope", wintypes.DWORD), ("remote_port", wintypes.DWORD),
                ("state", wintypes.DWORD), ("pid", wintypes.DWORD)]


def _port(raw: int) -> int:
    return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)            # the table stores the port in network byte order


def _read_table(family: int) -> bytes:
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        raise EnumerationError("unsupported_platform")
    function = windll.iphlpapi.GetExtendedTcpTable
    size = wintypes.DWORD(0)
    for _ in range(5):                                          # the table can grow between the two calls
        buffer = ctypes.create_string_buffer(size.value) if size.value else None
        status = function(buffer, ctypes.byref(size), False, family, _TCP_TABLE_OWNER_PID_LISTENER, 0)
        if status == 0:
            return buffer.raw[:size.value]
        if status != _ERROR_INSUFFICIENT_BUFFER:
            raise EnumerationError("table_unreadable")
    raise EnumerationError("table_unreadable")


def os_listeners() -> list[Listener]:
    """Every local TCP listener (IPv4 and IPv6) with its owning PID. Raises EnumerationError if the table is unreadable."""
    found: list[Listener] = []
    try:
        data = _read_table(_AF_INET)
        count = int.from_bytes(data[:4], "little")
        for row in (_Row4 * count).from_buffer_copy(data, 4):
            found.append(Listener(socket.inet_ntoa(row.local_addr.to_bytes(4, "little")), _port(row.local_port), row.pid or None))
        data = _read_table(_AF_INET6)
        count = int.from_bytes(data[:4], "little")
        for row in (_Row6 * count).from_buffer_copy(data, 4):
            address = ipaddress.IPv6Address(bytes(row.local_addr))
            text = f"{address}%{row.local_scope}" if row.local_scope else str(address)
            found.append(Listener(text, _port(row.local_port), row.pid or None))
    except EnumerationError:
        raise
    except (OSError, ValueError, AttributeError, MemoryError):
        raise EnumerationError("table_unreadable") from None
    return found


def os_process_info(pid: int) -> ProcessInfo | None:
    """The executable of a process, or None when it cannot be resolved (system processes, other users' processes)."""
    windll = getattr(ctypes, "windll", None)
    if windll is None or not isinstance(pid, int) or pid <= 4:
        return None
    kernel = windll.kernel32
    kernel.OpenProcess.restype = wintypes.HANDLE
    handle = kernel.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(MAX_PATH_CHARS)
        buffer = ctypes.create_unicode_buffer(MAX_PATH_CHARS)
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        path = buffer.value
    finally:
        kernel.CloseHandle(handle)
    return ProcessInfo(os.path.basename(path) or path, path) if path else None


def attribution(pid: int | None, ambiguous: bool, lookup=os_process_info) -> tuple[str, ProcessInfo | None]:
    """('attributed' | 'not_found' | 'unavailable', info). Never guesses: no PID or two owners means unavailable."""
    if pid is None or ambiguous:
        return "unavailable", None
    info = lookup(pid)
    return ("attributed", info) if info is not None else ("not_found", None)

