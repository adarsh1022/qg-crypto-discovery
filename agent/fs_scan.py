"""Filesystem certificate discovery (stdlib only).

Scan(config).records() walks the configured roots and yields one observation record per
certificate sighting (see agent/observations.py). Scan(...).summary reports counters, skip
reasons, errors and why the scan stopped.

What it does not do: write anything, follow links, talk to a backend, attribute owner
processes, or judge trust. It is read-only by construction: the only file operation is
open(path, "rb"), and bytes go straight into the parsers and are dropped.

Private-key safety: files that are not certificate candidates (.key, .csr, ...) are never
opened; candidate files are read once and handed to the Phase 1b parser, which never decodes,
stores or reports non-certificate blocks. PKCS#12 content (by sniffing, whatever the file is
called) goes to agent/pfx_bridge.py, which skips key bags undecoded and never gives a key
container to the OS (see its docstring for the one documented limitation).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import os
import stat
import time

from .cert_file import parse_cert_bytes
from .observations import file_record, iso_utc, records_from_file_parse, safe_text
from .pfx_bridge import read_pkcs12
from .scan_config import ScanConfig

MAX_LISTED_ERRORS = 1000

_ATTR_DIRECTORY = 0x10
_ATTR_REPARSE_POINT = 0x400
# OneDrive-style placeholders: opening the file would download it, so we never do
_ATTR_CLOUD_PLACEHOLDER = 0x1000 | 0x40000 | 0x400000      # OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS


def error_code(exc: OSError) -> str:
    """Fixed-format code for an OS error. Never includes the OS message (it can quote paths/data)."""
    winerror = getattr(exc, "winerror", None)
    if winerror:
        return f"{type(exc).__name__}:WinError {winerror}"
    return f"{type(exc).__name__}:errno {exc.errno}"


def _read_status(exc: OSError) -> str:
    """access_denied for permission problems; read_error for everything else (vanished, I/O error, ...).

    Known limitation: on Windows, Python's open() reports a file locked by another process
    (sharing violation) as PermissionError/errno 13 with no winerror, so a locked file cannot be
    told apart from an ACL denial and is reported as access_denied.
    """
    return "access_denied" if isinstance(exc, PermissionError) else "read_error"


def _read_limited(path: str, cap: int) -> bytes | None:
    """Read at most `cap` bytes; None if the file turns out to be larger."""
    with open(path, "rb") as handle:
        data = handle.read(cap + 1)
    return None if len(data) > cap else data


class Scan:
    def __init__(self, config: ScanConfig, *, now=None, clock=None, should_stop=None):
        self._cfg = config
        self._now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self._clock = clock or time.monotonic
        self._should_stop = should_stop
        self._exts = frozenset(config.extensions)
        self._exclude_names = frozenset(config.exclude_dir_names)
        self._used = False
        self._t0 = None
        self._elapsed = None
        self._stop_reason = None
        self._seen: set[str] = set()
        self._roots: list[dict] = []
        self._errors: list[dict] = []
        self._c = dict(directories_visited=0, entries_visited=0, candidate_files=0, files_read=0,
                       records=0, duplicate_observations=0, bundles_truncated=0, errors_total=0)
        self._by_status: dict[str, int] = {}
        self._skipped: dict[str, int] = {}

    # ------------------------------------------------------------ public
    @property
    def summary(self) -> dict:
        elapsed = self._elapsed if self._elapsed is not None else (
            self._clock() - self._t0 if self._t0 is not None else 0.0)
        return {
            "roots": [{"root": safe_text(r["root"]), "status": r["status"]} for r in self._roots],
            "directories_visited": self._c["directories_visited"],
            "entries_visited": self._c["entries_visited"],
            "candidate_files": self._c["candidate_files"],
            "files_read": self._c["files_read"],
            "records": self._c["records"],
            "records_by_status": dict(self._by_status),
            "unique_certificates": len(self._seen),
            "duplicate_observations": self._c["duplicate_observations"],
            "bundles_truncated": self._c["bundles_truncated"],
            "skipped": dict(self._skipped),
            "errors": [dict(e) for e in self._errors],
            "errors_total": self._c["errors_total"],
            "stop_reason": self._stop_reason,
            "complete": self._stop_reason == "completed",
            "elapsed_seconds": round(elapsed, 3),
        }

    def records(self):
        """Yield observation records. A Scan can be consumed once."""
        if self._used:
            raise RuntimeError("a Scan can be consumed only once")
        self._used = True
        self._t0 = self._clock()
        try:
            self._roots = self._plan_roots()
            for root in self._roots:
                if root["status"] != "pending":
                    continue
                if self._halt():
                    root["status"] = "not_reached"
                    continue
                yield from self._walk(root)
            for root in self._roots:
                if root["status"] == "pending":
                    root["status"] = "not_reached"
        except GeneratorExit:
            self._stop_reason = self._stop_reason or "cancelled"
            raise
        finally:
            self._stop_reason = self._stop_reason or "completed"
            self._elapsed = self._clock() - self._t0

    # ------------------------------------------------------------ helpers
    def _halt(self) -> bool:
        if self._stop_reason:
            return True
        if self._should_stop is not None and self._should_stop():
            self._stop_reason = "cancelled"
            return True
        if self._clock() - self._t0 > self._cfg.time_budget_seconds:
            self._stop_reason = "time_limit"
            return True
        return False

    def _skip(self, reason: str) -> None:
        self._skipped[reason] = self._skipped.get(reason, 0) + 1

    def _error(self, path: str, kind: str, exc: OSError) -> None:
        self._c["errors_total"] += 1
        if len(self._errors) < MAX_LISTED_ERRORS:
            self._errors.append({"path": safe_text(path), "kind": kind, "code": error_code(exc)})

    def _emit(self, record: dict) -> dict:
        digest = record["sha256"]
        if digest is not None:
            if digest in self._seen:
                record["duplicate_in_scan"] = True
                self._c["duplicate_observations"] += 1
            else:
                self._seen.add(digest)
        self._c["records"] += 1
        status = record["parse_status"]
        self._by_status[status] = self._by_status.get(status, 0) + 1
        return record

    # ------------------------------------------------------------ roots
    def _excluded_by_config(self, norm_path: str) -> bool:
        return any(norm_path == p or norm_path.startswith(p + os.sep) for p in self._cfg.exclude_paths)

    def _plan_roots(self) -> list[dict]:
        plan = []
        for configured in self._cfg.roots:
            item = {"root": configured, "status": "pending", "_real": None}
            try:
                st = os.stat(configured)                       # follows links: roots are explicit intent
            except OSError as exc:
                item["status"] = "access_denied" if isinstance(exc, PermissionError) else "not_found"
                self._error(configured, "root", exc)
            else:
                if not stat.S_ISDIR(st.st_mode):
                    item["status"] = "not_a_directory"
                else:
                    item["_real"] = os.path.normcase(os.path.realpath(configured))
            plan.append(item)

        # collapse overlapping roots so the same file is never reported twice
        valid = [(i, p["_real"]) for i, p in enumerate(plan) if p["_real"]]
        for i, real in valid:
            for j, other in valid:
                if i == j:
                    continue
                if real == other:
                    covered = j < i
                elif real.startswith(other + os.sep):
                    rel = real[len(other) + 1:].split(os.sep)
                    covered = (len(rel) <= self._cfg.max_depth
                               and not any(part in self._exclude_names for part in rel)
                               and not self._excluded_by_config(real))
                else:
                    covered = False
                if covered:
                    plan[i]["status"] = "overlap"
                    self._skip("root_overlap")
                    break
        for item in plan:
            item.pop("_real")
        return plan

    # ------------------------------------------------------------ traversal
    def _walk(self, root: dict):
        cfg = self._cfg
        stack = [(root["root"], 0)]
        while stack:
            if self._halt():
                root["status"] = "partial"
                return
            directory, depth = stack.pop()
            try:
                with os.scandir(directory) as it:
                    entries = sorted(it, key=lambda e: e.name.casefold())
            except OSError as exc:
                self._error(directory, "listdir", exc)
                continue
            self._c["directories_visited"] += 1

            subdirs = []
            for entry in entries:
                self._c["entries_visited"] += 1
                if self._c["entries_visited"] > cfg.max_entries:
                    self._stop_reason = self._stop_reason or "entry_limit"
                if self._halt():
                    root["status"] = "partial"
                    return
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    self._error(entry.path, "stat", exc)
                    continue
                attrs = getattr(st, "st_file_attributes", None)
                is_reparse = bool((attrs or 0) & _ATTR_REPARSE_POINT) or entry.is_symlink()
                is_dir = bool(attrs & _ATTR_DIRECTORY) if attrs is not None else stat.S_ISDIR(st.st_mode)

                if is_dir:
                    if is_reparse:
                        self._skip("reparse_dir")
                    elif depth + 1 > cfg.max_depth:
                        self._skip("depth_limit")
                    elif (entry.name.casefold() in self._exclude_names
                          or self._excluded_by_config(os.path.normcase(entry.path))):
                        self._skip("excluded_dir")
                    else:
                        subdirs.append(entry.path)
                    continue

                ext = os.path.splitext(entry.name)[1].casefold()
                if ext not in self._exts:
                    continue                                   # not a candidate: never opened
                if self._c["candidate_files"] >= cfg.max_candidates:
                    self._stop_reason = self._stop_reason or "candidate_limit"
                    root["status"] = "partial"
                    return
                self._c["candidate_files"] += 1
                yield from self._candidate(entry, st, attrs or 0, is_reparse, ext, root["root"])

            stack.extend((p, depth + 1) for p in reversed(subdirs))
        root["status"] = "scanned"

    def _file_rec(self, entry, scan_root, status, detail, access_error=None) -> dict:
        return self._emit(file_record(entry.path, entry.name, scan_root, "unknown",
                                      iso_utc(self._now()), status, detail, access_error))

    def _candidate(self, entry, st, attrs: int, is_reparse: bool, ext: str, scan_root: str):
        cfg = self._cfg
        if attrs & _ATTR_CLOUD_PLACEHOLDER:
            self._skip("cloud_placeholder")
            yield self._file_rec(entry, scan_root, "skipped", "cloud_placeholder")
            return
        if is_reparse:
            self._skip("reparse_file")
            return
        if not stat.S_ISREG(st.st_mode):
            self._skip("not_regular_file")
            return
        if st.st_size > cfg.max_file_bytes:
            yield self._file_rec(entry, scan_root, "too_large", "file_too_large")
            return

        try:
            data = _read_limited(entry.path, cfg.max_file_bytes)
        except OSError as exc:
            self._error(entry.path, "read", exc)
            yield self._file_rec(entry, scan_root, _read_status(exc), "read_failed", error_code(exc))
            return
        except Exception:                                      # noqa: BLE001 - per-file isolation
            yield self._file_rec(entry, scan_root, "read_error", "internal_error")
            return
        if data is None:
            yield self._file_rec(entry, scan_root, "too_large", "file_too_large")
            return
        self._c["files_read"] += 1
        stamp = self._now()

        try:
            parsed = parse_cert_bytes(data, filename_hint=entry.name,
                                      max_certs=cfg.max_certs_per_file, max_size=cfg.max_file_bytes)
            if parsed.format == "pkcs12":                      # by content: .pfx, .p12 or any other name
                parsed = dataclasses.replace(read_pkcs12(data, max_certs=cfg.max_certs_per_file),
                                             extension_mismatch=parsed.extension_mismatch)
        except Exception:                                      # noqa: BLE001 - per-file isolation
            yield self._file_rec(entry, scan_root, "read_error", "internal_error")
            return
        finally:
            del data                                           # drop the file bytes immediately
        if parsed.truncated:
            self._c["bundles_truncated"] += 1
        for rec in records_from_file_parse(entry.path, entry.name, scan_root, parsed, stamp,
                                           cfg.expiring_days):
            yield self._emit(rec)
