"""The agent's run loop: find a queued filesystem run, claim it, scan, upload in bounded batches, finish.

How a claimed run is handled:
  * the run's `config` is turned into a ScanConfig by the agent itself (the agent decides what is valid); a bad config
    finishes the run as failed (`invalid_config`) without scanning;
  * a background thread sends heartbeats, because a long directory walk can go quiet for longer than the lease allows;
    it also learns about cancellation and about a lost lease;
  * records are streamed from the scan into numbered batches (seq 0, 1, 2, ...) no larger than the server's limits.
    Uploads are idempotent by seq, so a batch that may not have arrived is simply sent again;
  * on cancellation the scan stops cooperatively, what was found so far is uploaded and the run is finished normally
    (the backend marks it partial); on a lost lease the agent stops and does not keep hammering the backend.

The lease token stays in local variables. Log lines carry counts and fixed codes only: never the token, a path,
or any certificate content.
"""
from __future__ import annotations

import json
import logging
import platform
import re
import socket
import threading
import time
from dataclasses import dataclass

from agent.client import BackendClient, BackendError, Unreachable
from agent.fs_scan import Scan
from agent.scan_config import ConfigError, ScanConfig
from agent.tls_scan import TlsScan, TlsScanConfig

AGENT_VERSION = "0.1.0"
log = logging.getLogger("agent.runner")


@dataclass(frozen=True)
class RunnerOptions:
    agent_id: str
    hostname: str
    os_name: str | None = None
    batch_size: int = 200               # records per upload (also capped by the server's limit)
    upload_retries: int = 4             # extra attempts after a network failure (replay is safe: uploads are idempotent)
    retry_delay: float = 0.5
    list_limit: int = 100


@dataclass
class RunReport:
    run_id: str
    outcome: str = "unknown"            # finished | failed | lost | unreachable
    detail: str | None = None           # fixed code, e.g. invalid_config
    records_sent: int = 0
    accepted: int = 0
    duplicates: int = 0
    rejected: int = 0
    conflicts: int = 0
    batches: int = 0
    cancelled: bool = False
    final_status: str | None = None     # the backend's final run status, when known


def default_options(agent_id: str | None = None, batch_size: int = 200) -> RunnerOptions:
    host = (socket.gethostname() or "unknown-host")[:100]
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", host) or "host"
    return RunnerOptions(agent_id=agent_id or f"agent-{safe}"[:128], hostname=host,
                         os_name=platform.platform()[:200] or None, batch_size=batch_size)


# --------------------------------------------------------------------------------------------------- polling
def poll_once(client: BackendClient, options: RunnerOptions, shutdown: threading.Event | None = None,
              scan_factory=Scan, tls_scan_factory=TlsScan) -> RunReport | None:
    """Claim and process at most one queued run (oldest first, whatever its type). None if there was nothing to do."""
    runs = sorted(client.queued_runs(options.list_limit), key=lambda r: r.get("run_number", 0))
    for run in runs:
        try:
            claim = client.claim(run["run_id"], agent_id=options.agent_id, hostname=options.hostname,
                                 os_name=options.os_name, agent_version=AGENT_VERSION)
        except BackendError as exc:
            if exc.status in (404, 409):            # someone else took it, it expired or was cancelled: try the next one
                log.info("run %s not claimable: %s", run["run_id"], exc.code)
                continue
            raise
        return run_claimed(client, claim, options, shutdown or threading.Event(), scan_factory=scan_factory,
                           tls_scan_factory=tls_scan_factory)
    return None


def serve_forever(client: BackendClient, options: RunnerOptions, shutdown: threading.Event, poll_interval: float = 3.0,
                  scan_factory=Scan, tls_scan_factory=TlsScan) -> None:
    delay = poll_interval
    while not shutdown.is_set():
        try:
            report = poll_once(client, options, shutdown, scan_factory, tls_scan_factory)
            delay = poll_interval
        except Unreachable:
            log.warning("backend not reachable; retrying")
            delay = min(max(delay * 2, poll_interval), 30.0)
            report = None
        except BackendError as exc:
            log.warning("backend refused the poll (%s %s)", exc.status, exc.code)
            delay, report = min(max(delay * 2, poll_interval), 30.0), None
        if report is not None:
            log.info("run %s: %s%s (%d records, %d batches)", report.run_id, report.outcome,
                     f" [{report.detail}]" if report.detail else "", report.records_sent, report.batches)
            continue                                 # more work may be waiting: poll again at once
        shutdown.wait(delay)


# --------------------------------------------------------------------------------------------------- one run
class _Lease:
    """What the heartbeat thread tells the scanning thread."""

    def __init__(self):
        self.cancel = threading.Event()
        self.lost = threading.Event()
        self.stop = threading.Event()                # set by the owner to end the heartbeat thread


def _heartbeat_loop(client: BackendClient, run_id: str, token: str, interval: float, timeout: float, lease: _Lease) -> None:
    last_ok = time.monotonic()
    while not lease.stop.wait(interval):
        try:
            answer = client.heartbeat(run_id, token)
            last_ok = time.monotonic()
            if answer.get("cancel_requested"):
                lease.cancel.set()
            if answer.get("status") != "running":
                lease.lost.set()
                return
        except BackendError as exc:
            log.warning("heartbeat refused (%s %s)", exc.status, exc.code)
            lease.lost.set()
            return
        except Unreachable:
            if time.monotonic() - last_ok > timeout:
                log.warning("heartbeat: backend unreachable for longer than the lease timeout")
                lease.lost.set()
                return


def _fail(client: BackendClient, run_id: str, token: str, report: RunReport, code: str, summary: dict | None = None) -> RunReport:
    report.outcome, report.detail = "failed", code
    try:
        report.final_status = client.finish(run_id, token, outcome="failed", summary=summary, fatal_code=code)["run"].get("status")
    except BackendError as exc:
        report.final_status = None
        log.warning("could not report failure %s (%s %s)", code, exc.status, exc.code)
    except Unreachable:
        log.warning("could not report failure %s: backend unreachable", code)
    return report


def run_claimed(client: BackendClient, claim: dict, options: RunnerOptions, shutdown: threading.Event, scan_factory=Scan,
                tls_scan_factory=TlsScan) -> RunReport:
    run, token = claim["run"], claim["lease_token"]
    run_id = run["run_id"]
    lease_info, limits = claim.get("lease", {}), claim.get("limits", {})
    report = RunReport(run_id)
    log.info("claimed run %s", run_id)

    # The scanner follows the run's type. Everything below (heartbeats, batching, retries, cancellation, lease loss,
    # shutdown) is the same for both: a scan is anything with records() and summary.
    if run.get("type") == "tls":
        config_class, factory = TlsScanConfig, tls_scan_factory
    elif run.get("type") == "filesystem":
        config_class, factory = ScanConfig, scan_factory
    else:
        log.warning("run %s has a type this agent cannot execute", run_id)
        return _fail(client, run_id, token, report, "unsupported_run_type")
    try:
        config = config_class.from_dict(run.get("config") or {})
    except (ConfigError, TypeError, ValueError):
        log.warning("run %s has an invalid scan configuration", run_id)
        return _fail(client, run_id, token, report, "invalid_config")

    timeout = float(lease_info.get("heartbeat_timeout_s", 90))
    interval = max(0.05, min(float(lease_info.get("heartbeat_interval_s", 15)), timeout / 3))
    max_items = max(1, min(options.batch_size, int(limits.get("max_batch_items", 500))))
    max_bytes = max(1024, int(limits.get("max_body_bytes", 2 * 1024 * 1024)) // 2)    # headroom for JSON overhead

    lease = _Lease()
    beat = threading.Thread(target=_heartbeat_loop, args=(client, run_id, token, interval, timeout, lease),
                            name="heartbeat", daemon=True)
    beat.start()
    try:
        scan = factory(config, should_stop=lambda: lease.cancel.is_set() or lease.lost.is_set() or shutdown.is_set())
        _stream(client, run_id, token, scan, report, lease, max_items, max_bytes, options)
        if lease.lost.is_set():
            report.outcome, report.detail = "lost", "lease_lost"
            log.warning("run %s: lease lost; stopping", run_id)
            return report
        if shutdown.is_set() and not lease.cancel.is_set():
            return _fail(client, run_id, token, report, "agent_stopped", summary=scan.summary)
        report.cancelled = lease.cancel.is_set()
        try:
            report.final_status = _retrying(options, lambda: client.finish(
                run_id, token, outcome="finished", summary=scan.summary))["run"].get("status")
            report.outcome = "finished"
        except BackendError as exc:
            if exc.status == 409 and exc.code == "run_already_finished":
                final = exc.details.get("run") if isinstance(exc.details, dict) else None
                report.outcome = "finished"
                report.final_status = final.get("status") if isinstance(final, dict) else None
            else:
                report.outcome, report.detail = "lost", exc.code
        return report
    except _Lost:
        report.outcome, report.detail = "lost", "lease_lost"
        return report
    except Unreachable:
        report.outcome, report.detail = "unreachable", "backend_unreachable"
        log.warning("run %s: backend unreachable; the backend will expire the run", run_id)
        return report
    except BackendError as exc:
        report.outcome, report.detail = "lost", exc.code
        log.warning("run %s: backend refused (%s %s)", run_id, exc.status, exc.code)
        return report
    except KeyboardInterrupt:                        # Ctrl+C: tell the backend rather than leave the lease to expire
        _fail(client, run_id, token, report, "agent_stopped")
        raise
    except Exception as exc:                         # a scanner/agent bug: say so, with the class name only
        log.error("run %s: unexpected %s", run_id, type(exc).__name__)
        return _fail(client, run_id, token, report, "agent_error")
    finally:
        lease.stop.set()
        beat.join(timeout=5)


class _Lost(Exception):
    pass


def _record_size(record) -> int:
    return len(json.dumps(record, ensure_ascii=True, separators=(",", ":"))) + 12


def _stream(client, run_id, token, scan, report: RunReport, lease: _Lease, max_items: int, max_bytes: int,
            options: RunnerOptions) -> None:
    seq = 0
    batch: list = []
    size = 0
    for record in scan.records():
        item_size = _record_size(record)
        if batch and (len(batch) >= max_items or size + item_size > max_bytes):
            _send(client, run_id, token, batch, report, lease, options)
            batch, size = [], 0
        batch.append([seq, record])
        seq += 1
        size += item_size
        report.records_sent += 1
    if batch and not lease.lost.is_set():
        _send(client, run_id, token, batch, report, lease, options)


def _retrying(options: RunnerOptions, call, lease: _Lease | None = None):
    """Run `call`, repeating it after a network failure. Safe because uploads are idempotent by seq and a repeated
    finish is answered 'run_already_finished'."""
    attempt = 0
    while True:
        try:
            return call()
        except Unreachable:
            attempt += 1
            if attempt > options.upload_retries or (lease is not None and lease.lost.is_set()):
                raise
            time.sleep(options.retry_delay)


def _send(client, run_id, token, batch: list, report: RunReport, lease: _Lease, options: RunnerOptions) -> None:
    if lease.lost.is_set():
        raise _Lost()
    answer = _retrying(options, lambda: client.upload(run_id, token, batch), lease)
    report.batches += 1
    report.accepted += int(answer.get("accepted", 0))
    report.duplicates += int(answer.get("duplicates", 0))
    report.rejected += len(answer.get("rejected") or [])
    report.conflicts += len(answer.get("conflicts") or [])
    if report.rejected or report.conflicts:
        log.warning("run %s: batch had %d rejected and %d conflicting items", run_id,
                    len(answer.get("rejected") or []), len(answer.get("conflicts") or []))
    if answer.get("cancel_requested"):
        lease.cancel.set()
    if answer.get("status") != "running":
        lease.lost.set()
        raise _Lost()
