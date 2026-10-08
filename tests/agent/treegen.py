"""Test-only helpers for building directory trees and Windows filesystem edge cases."""
from __future__ import annotations

import contextlib
import ctypes
import datetime as dt
import os
import subprocess
from ctypes import wintypes
from pathlib import Path

from agent.fs_scan import Scan
from agent.scan_config import ScanConfig

NOW = dt.datetime(2025, 6, 1, 12, 0, 0, tzinfo=dt.timezone.utc)

FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_NORMAL = 0x80


def put(root: Path, rel: str, data: bytes) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def run_scan(*roots, now=NOW, clock=None, should_stop=None, **config):
    """-> (records, summary). `roots` are paths; `config` are ScanConfig fields."""
    scan = Scan(ScanConfig(roots=tuple(str(r) for r in roots), **config),
                now=lambda: now, clock=clock, should_stop=should_stop)
    records = list(scan.records())
    return records, scan.summary


class StepClock:
    """A fake monotonic clock that advances `step` seconds every time it is read."""

    def __init__(self, step: float):
        self.t, self.step = 0.0, step

    def __call__(self) -> float:
        self.t += self.step
        return self.t


def make_junction(link: Path, target: Path) -> bool:
    """NTFS junction (needs no privileges). Returns False if it could not be created."""
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                            capture_output=True, text=True)
    return result.returncode == 0


def try_symlink(link: Path, target: Path, is_dir: bool) -> bool:
    try:
        os.symlink(target, link, target_is_directory=is_dir)
        return True
    except (OSError, NotImplementedError):
        return False


def _kernel32():
    k = ctypes.windll.kernel32
    k.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    k.SetFileAttributesW.restype = wintypes.BOOL
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                              wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k.CreateFileW.restype = wintypes.HANDLE
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    return k


@contextlib.contextmanager
def offline_attribute(path: Path):
    """Mark a file like a cloud placeholder (FILE_ATTRIBUTE_OFFLINE); always restored."""
    k = _kernel32()
    assert k.SetFileAttributesW(str(path), FILE_ATTRIBUTE_OFFLINE)
    try:
        yield
    finally:
        k.SetFileAttributesW(str(path), FILE_ATTRIBUTE_NORMAL)


@contextlib.contextmanager
def file_attributes(path: Path, flags: int):
    """Temporarily set Windows file attributes (e.g. HIDDEN|SYSTEM = 0x6); always restored."""
    k = _kernel32()
    assert k.SetFileAttributesW(str(path), flags)
    try:
        yield
    finally:
        k.SetFileAttributesW(str(path), FILE_ATTRIBUTE_NORMAL)


@contextlib.contextmanager
def exclusive_lock(path: Path):
    """Hold the file open with no sharing, so another open fails with a real WinError 32."""
    k = _kernel32()
    handle = k.CreateFileW(str(path), 0xC0000000, 0, None, 3, FILE_ATTRIBUTE_NORMAL, None)
    assert handle not in (None, ctypes.c_void_p(-1).value), "could not lock file"
    try:
        yield
    finally:
        k.CloseHandle(handle)
