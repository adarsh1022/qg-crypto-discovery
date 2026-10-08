"""Filesystem scan configuration and default scan roots (stdlib only).

ScanConfig is a frozen, validated value object. The backend will later pass the same
fields as JSON through ScanConfig.from_dict().

default_roots() only ever returns directories that exist on this machine; nothing is guessed.
"""
from __future__ import annotations

import ctypes
import os
import uuid
from dataclasses import dataclass, fields

DEFAULT_EXTENSIONS = (".pem", ".crt", ".cer", ".cert", ".der", ".pfx", ".p12")
DEFAULT_EXCLUDE_DIR_NAMES = ("$Recycle.Bin", "System Volume Information", "WinSxS", ".git",
                             "node_modules")

DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_DEPTH = 12
DEFAULT_MAX_ENTRIES = 1_000_000
DEFAULT_MAX_CANDIDATES = 50_000
DEFAULT_MAX_CERTS_PER_FILE = 1000
DEFAULT_TIME_BUDGET_SECONDS = 600.0
DEFAULT_EXPIRING_DAYS = 30


class ConfigError(ValueError):
    """Invalid scan configuration."""


# ---------------------------------------------------------------- default roots
_FOLDERID_DOWNLOADS = "374DE290-123F-4565-9164-39C4925E467B"
_FOLDERID_DOCUMENTS = "FDD39AD0-238F-46AF-ADB4-6C85480369C7"
_FOLDERID_DESKTOP = "B4BFCC3A-DB2C-424C-B029-7FE99A87C641"


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]


def _windows_known_folder(folder_id: str) -> str | None:
    """Real location of a user folder (follows OneDrive/redirection), or None."""
    if os.name != "nt":
        return None
    try:
        u = uuid.UUID(folder_id)
        guid = _GUID(u.time_low, u.time_mid, u.time_hi_version, (ctypes.c_ubyte * 8)(*u.bytes[8:]))
        fn = ctypes.windll.shell32.SHGetKnownFolderPath
        fn.argtypes = [ctypes.POINTER(_GUID), ctypes.c_uint32, ctypes.c_void_p,
                       ctypes.POINTER(ctypes.c_wchar_p)]
        fn.restype = ctypes.c_long
        out = ctypes.c_wchar_p()
        if fn(ctypes.byref(guid), 0, None, ctypes.byref(out)) != 0:
            return None
        value = out.value
        free = ctypes.windll.ole32.CoTaskMemFree
        free.argtypes = [ctypes.c_void_p]
        free(ctypes.cast(out, ctypes.c_void_p))
        return value
    except Exception:                                   # noqa: BLE001 - any failure -> fallback path
        return None


def default_roots(env=None, known_folder=_windows_known_folder, isdir=os.path.isdir) -> list[str]:
    """Existing, de-duplicated default roots: user folders, .aspnet/https, ProgramData, Git."""
    env = os.environ if env is None else env
    home = env.get("USERPROFILE") or os.path.expanduser("~")
    candidates = [
        known_folder(_FOLDERID_DOWNLOADS) or os.path.join(home, "Downloads"),
        known_folder(_FOLDERID_DOCUMENTS) or os.path.join(home, "Documents"),
        known_folder(_FOLDERID_DESKTOP) or os.path.join(home, "Desktop"),
        os.path.join(home, ".aspnet", "https"),
    ]
    if env.get("ProgramData"):
        candidates.append(env["ProgramData"])
    if env.get("ProgramFiles"):
        candidates.append(os.path.join(env["ProgramFiles"], "Git"))

    roots, seen = [], set()
    for c in candidates:
        if not c or not isdir(c):
            continue
        key = os.path.normcase(os.path.normpath(c))
        if key not in seen:
            seen.add(key)
            roots.append(os.path.normpath(c))
    return roots


# ---------------------------------------------------------------- config
def _positive_int(name: str, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{name} must be a positive integer")
    return value


def _norm_extension(ext) -> str:
    if not isinstance(ext, str):
        raise ConfigError("extensions must be strings")
    ext = ext.strip().casefold()
    if ext and not ext.startswith("."):
        ext = "." + ext
    if len(ext) < 2 or "/" in ext or "\\" in ext or ext[1:].startswith("."):
        raise ConfigError(f"invalid extension: {ext!r}")
    return ext


@dataclass(frozen=True)
class ScanConfig:
    roots: tuple[str, ...] | None = None          # None -> default_roots()
    extensions: tuple[str, ...] = DEFAULT_EXTENSIONS
    exclude_dir_names: tuple[str, ...] = DEFAULT_EXCLUDE_DIR_NAMES
    exclude_paths: tuple[str, ...] = ()
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_entries: int = DEFAULT_MAX_ENTRIES
    max_candidates: int = DEFAULT_MAX_CANDIDATES
    max_certs_per_file: int = DEFAULT_MAX_CERTS_PER_FILE
    time_budget_seconds: float = DEFAULT_TIME_BUDGET_SECONDS
    expiring_days: int = DEFAULT_EXPIRING_DAYS

    def __post_init__(self):
        def put(name, value):
            object.__setattr__(self, name, value)

        roots = default_roots() if self.roots is None else self.roots
        if isinstance(roots, (str, bytes)):
            raise ConfigError("roots must be a list of paths")
        clean = []
        for r in roots:
            if not isinstance(r, str) or not r:
                raise ConfigError("each root must be a non-empty string")
            if r.startswith("\\\\") or r.startswith("//"):
                raise ConfigError("network (UNC) roots are not supported")
            if not os.path.isabs(r):
                raise ConfigError(f"root must be an absolute path: {r!r}")
            clean.append(os.path.normpath(r))
        if not clean:
            raise ConfigError("no scan roots (none configured and no default location exists)")
        put("roots", tuple(clean))

        exts = tuple(dict.fromkeys(_norm_extension(e) for e in self.extensions))
        if not exts:
            raise ConfigError("extensions must not be empty")
        put("extensions", exts)

        names = []
        for n in self.exclude_dir_names:
            if not isinstance(n, str) or not n or "/" in n or "\\" in n:
                raise ConfigError(f"invalid excluded directory name: {n!r}")
            names.append(n.casefold())
        put("exclude_dir_names", tuple(dict.fromkeys(names)))

        paths = []
        for p in self.exclude_paths:
            if not isinstance(p, str) or not os.path.isabs(p):
                raise ConfigError(f"excluded path must be absolute: {p!r}")
            paths.append(os.path.normcase(os.path.normpath(p)))
        put("exclude_paths", tuple(dict.fromkeys(paths)))

        _positive_int("max_file_bytes", self.max_file_bytes)
        _positive_int("max_entries", self.max_entries)
        _positive_int("max_candidates", self.max_candidates)
        _positive_int("max_certs_per_file", self.max_certs_per_file)
        if isinstance(self.max_depth, bool) or not isinstance(self.max_depth, int) or self.max_depth < 0:
            raise ConfigError("max_depth must be a non-negative integer")
        if (isinstance(self.expiring_days, bool) or not isinstance(self.expiring_days, int)
                or self.expiring_days < 0):
            raise ConfigError("expiring_days must be a non-negative integer")
        if (isinstance(self.time_budget_seconds, bool)
                or not isinstance(self.time_budget_seconds, (int, float))
                or self.time_budget_seconds <= 0):
            raise ConfigError("time_budget_seconds must be a positive number")

    @classmethod
    def from_dict(cls, data: dict) -> "ScanConfig":
        if not isinstance(data, dict):
            raise ConfigError("scan configuration must be an object")
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ConfigError(f"unknown configuration keys: {sorted(unknown)}")
        kwargs = {}
        for key, value in data.items():
            kwargs[key] = tuple(value) if isinstance(value, list) else value
        return cls(**kwargs)
