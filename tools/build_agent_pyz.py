#!/usr/bin/env python3
"""Build the agent as ONE small, runnable archive:  dist/qg-agent.pyz

    python tools/build_agent_pyz.py                      # writes dist/qg-agent.pyz and prints its size and SHA-256
    python dist/qg-agent.pyz --help                      # same options as `python -m agent --help`
    python dist/qg-agent.pyz --server http://127.0.0.1:8765

What goes in: the agent's own Python source (`agent/**/*.py`, nothing else) and a two-line `__main__.py` that calls
`agent.__main__.main()`. What stays out: virtual environments, `__pycache__`, tests, fixtures, the backend and the frontend. The
agent uses only the Python standard library, so no dependency is bundled and no interpreter is included: running the archive needs
Python 3.11 on the machine (and, as always, Windows for the OS-specific parts).

The build is reproducible: entries are sorted, carry a fixed timestamp and permissions, and source line endings are normalised to
LF, so the same source gives the same bytes (and the same SHA-256) on any checkout. It fails (exit code 1) if the archive would be
larger than the 5 MB limit. Standard library only; run it with any Python 3.9+.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import pathlib
import sys
import zipfile

REPO = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = REPO / "agent"
DEFAULT_OUTPUT = REPO / "dist" / "qg-agent.pyz"
LIMIT_BYTES = 5 * 1024 * 1024                                  # the assignment's limit for the agent package
SHEBANG = b"#!/usr/bin/env python3\n"
MAIN_PY = b"from agent.__main__ import main\nraise SystemExit(main())\n"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)                             # the earliest time a zip can hold: no build time leaks in


def collect(source: pathlib.Path) -> list[pathlib.Path]:
    """Every Python source file of the agent package, in a fixed order. Caches and other file types are never included."""
    if not source.is_dir():
        raise SystemExit(f"error: the agent source folder {source} does not exist")
    files = sorted((p for p in source.rglob("*.py") if "__pycache__" not in p.parts), key=lambda p: p.relative_to(source).as_posix())
    if not any(p.name == "__main__.py" for p in files):
        raise SystemExit(f"error: {source} has no __main__.py, so it is not the agent package")
    return files


def build(source: pathlib.Path = DEFAULT_SOURCE) -> bytes:
    """The archive's bytes. The first line is a shebang so the file can also be started directly where that works."""
    entries = [("__main__.py", MAIN_PY)]
    for path in collect(source):
        entries.append((f"{source.name}/{path.relative_to(source).as_posix()}", path.read_bytes().replace(b"\r\n", b"\n")))
    buffer = io.BytesIO()
    buffer.write(SHEBANG)
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.create_system = 3                              # the same on every platform
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return buffer.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the agent as a single runnable .pyz archive (standard library only).")
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT, help="where to write it (default: dist/qg-agent.pyz)")
    parser.add_argument("--source", type=pathlib.Path, default=DEFAULT_SOURCE, help="the agent package folder (default: agent/)")
    parser.add_argument("--limit-bytes", type=int, default=LIMIT_BYTES, help="fail if the archive is larger than this (default: 5 MB)")
    args = parser.parse_args(argv)

    data = build(args.source)
    if len(data) > args.limit_bytes:
        print(f"error: the archive would be {len(data):,} bytes, over the limit of {args.limit_bytes:,} bytes; nothing was written", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    count = len(zipfile.ZipFile(io.BytesIO(data)).namelist())
    print(f"wrote {args.output}")
    print(f"  size    {len(data):,} bytes ({len(data) / 1024:.1f} KiB; limit {args.limit_bytes:,} bytes, {100 * len(data) / args.limit_bytes:.2f}% used)")
    print(f"  sha256  {hashlib.sha256(data).hexdigest()}")
    print(f"  files   {count} (agent source plus __main__.py; no dependencies, no interpreter)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
