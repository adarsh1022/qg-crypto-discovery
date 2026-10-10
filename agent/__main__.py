"""Run the discovery agent:  python -m agent [--server http://127.0.0.1:8765] [--poll-interval 3] [--once]

The agent polls the local backend for queued filesystem runs, scans, and uploads the results. Ctrl+C stops it
(a run in progress is finished as failed with `agent_stopped`)."""
from __future__ import annotations

import argparse
import logging
import re
import sys
import threading

from agent.client import BackendClient, BackendError, Unreachable
from agent.runner import default_options, poll_once, serve_forever


def _bounded(low: float, high: float):
    def parse(text: str) -> float:
        value = float(text)
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return value
    return parse


def _agent_id(text: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", text):
        raise argparse.ArgumentTypeError("use letters, digits, '.', '_' and '-' (max 128)")
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent", description="Local certificate-discovery agent.")
    parser.add_argument("--server", default="http://127.0.0.1:8765", help="backend URL (loopback only; default %(default)s)")
    parser.add_argument("--poll-interval", type=_bounded(0.5, 60), default=3.0, help="seconds between polls (default 3)")
    parser.add_argument("--once", action="store_true", help="process at most one queued run, then exit")
    parser.add_argument("--agent-id", type=_agent_id, default=None, help="agent identifier (default: derived from the host name)")
    parser.add_argument("--batch-size", type=int, choices=range(1, 501), metavar="1-500", default=200, help="records per upload")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    args = parser.parse_args(argv)

    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        client = BackendClient(args.server)
    except ValueError as exc:
        parser.error(str(exc))
    options = default_options(args.agent_id, args.batch_size)

    if args.once:
        try:
            report = poll_once(client, options)
        except Unreachable:
            print("backend not reachable", file=sys.stderr)
            return 3
        except BackendError as exc:
            print(f"backend refused the request ({exc.status} {exc.code})", file=sys.stderr)
            return 3
        if report is None:
            print("no queued filesystem run")
            return 0
        print(f"run {report.run_id}: {report.outcome}" + (f" ({report.detail})" if report.detail else "")
              + f", {report.records_sent} records in {report.batches} batches")
        return 0 if report.outcome == "finished" else 1

    shutdown = threading.Event()
    print(f"agent {options.agent_id} polling {args.server} every {args.poll_interval:g}s (Ctrl+C to stop)")
    try:
        serve_forever(client, options, shutdown, args.poll_interval)
    except KeyboardInterrupt:
        shutdown.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
