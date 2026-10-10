"""Run the backend:  python -m backend [--db PATH] [--port 8765] [--data-origin agent|sample]

Binds to 127.0.0.1 only (there is deliberately no host option) and keeps uvicorn's per-request access log off."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

DEFAULT_PORT = 8765


def default_db_path() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) / "qg-crypto-discovery" if base else Path.home() / ".qg-crypto-discovery"
    return root / "agent.db"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend", description="Local certificate-discovery backend (127.0.0.1 only).")
    parser.add_argument("--db", type=Path, default=None, help="SQLite database file (default: %(prog)s uses a per-user data folder)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port on 127.0.0.1 (default %(default)s)")
    parser.add_argument("--data-origin", choices=("agent", "sample"), default="agent")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    try:
        import uvicorn
    except ImportError:
        print("uvicorn is not installed: pip install -r requirements-backend.txt", file=sys.stderr)
        return 2
    from backend.app import create_app
    from backend.settings import Settings

    db_path = (args.db or default_db_path()).expanduser().resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    app = create_app(Settings(db_path=db_path, data_origin=args.data_origin))
    print(f"backend: http://127.0.0.1:{args.port}  database: {db_path}  data origin: {args.data_origin}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
