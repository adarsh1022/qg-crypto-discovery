"""The TLS scan: probe the TLS services listening on THIS machine (stdlib only).

Method: ACTIVE LOCAL TLS SERVICE PROBING. The OS table of listening sockets is read, each eligible listener is probed once
(see agent/tls_probe.py and agent/tls_targets.py for exactly what a probe does and which addresses are allowed), and one
record per probe attempt is produced. This is not packet capture, and it does not observe other applications' traffic.

Shape (mirrors agent.fs_scan.Scan): `TlsScan(config, should_stop=...)`, a single-use `records()` generator, and a `summary`
property. Cancellation and the time budget are checked BETWEEN targets; one probe takes at most connect + handshake timeout.

Counts the summary reports are claims; the backend recomputes everything from the records it stored.
  records                one per probe that produced a record
  handshakes_completed   records whose handshake completed (the only ones the backend counts as TLS findings)
  policy_skipped         listeners whose destination the target policy refused (never probed)
  errors                 enumeration failures and probes that could not be made (kind "enumerate" or "probe")
"""
from __future__ import annotations

import datetime as dt
import time
from dataclasses import dataclass, fields

from .scan_config import ConfigError
from .tls_probe import ProbeAborted, Timeouts, probe
from .tls_targets import EnumerationError, attribution, build_plan, os_listeners, os_process_info

DEFAULT_MAX_TARGETS = 128
MAX_TARGETS_LIMIT = 1024
DEFAULT_CONNECT_TIMEOUT = 2.0
DEFAULT_HANDSHAKE_TIMEOUT = 3.0
MAX_TIMEOUT = 30.0
DEFAULT_TIME_BUDGET = 60.0
MAX_TIME_BUDGET = 3600.0
MAX_PORTS = 256
MAX_LISTED_ERRORS = 1000


def _positive_number(name: str, value, ceiling: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= ceiling:
        raise ConfigError(f"{name} must be a number above 0 and at most {ceiling:g}")
    return float(value)


@dataclass(frozen=True)
class TlsScanConfig:
    max_targets: int = DEFAULT_MAX_TARGETS
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT
    handshake_timeout_seconds: float = DEFAULT_HANDSHAKE_TIMEOUT
    time_budget_seconds: float = DEFAULT_TIME_BUDGET
    ports: tuple[int, ...] | None = None          # can only NARROW the OS listener table; never adds a target

    def __post_init__(self):
        if isinstance(self.max_targets, bool) or not isinstance(self.max_targets, int) or not 1 <= self.max_targets <= MAX_TARGETS_LIMIT:
            raise ConfigError(f"max_targets must be a whole number from 1 to {MAX_TARGETS_LIMIT}")
        object.__setattr__(self, "connect_timeout_seconds", _positive_number("connect_timeout_seconds", self.connect_timeout_seconds, MAX_TIMEOUT))
        object.__setattr__(self, "handshake_timeout_seconds", _positive_number("handshake_timeout_seconds", self.handshake_timeout_seconds, MAX_TIMEOUT))
        object.__setattr__(self, "time_budget_seconds", _positive_number("time_budget_seconds", self.time_budget_seconds, MAX_TIME_BUDGET))
        if self.ports is not None:
            ports = self.ports
            if isinstance(ports, (str, bytes)) or not isinstance(ports, (list, tuple)) or not 0 < len(ports) <= MAX_PORTS:
                raise ConfigError(f"ports must be a list of 1 to {MAX_PORTS} port numbers")
            if any(isinstance(p, bool) or not isinstance(p, int) or not 0 < p <= 65535 for p in ports):
                raise ConfigError("every port must be a whole number from 1 to 65535")
            object.__setattr__(self, "ports", tuple(dict.fromkeys(ports)))

    @classmethod
    def from_dict(cls, data: dict) -> "TlsScanConfig":
        if not isinstance(data, dict):
            raise ConfigError("scan configuration must be an object")
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ConfigError(f"unknown configuration keys: {sorted(unknown)}")
        return cls(**{key: (tuple(value) if isinstance(value, list) else value) for key, value in data.items()})


class TlsScan:
    def __init__(self, config: TlsScanConfig, *, now=None, clock=None, should_stop=None, listeners=os_listeners,
                 process_lookup=os_process_info, prober=probe):
        self._cfg = config
        self._now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self._clock = clock or time.monotonic
        self._should_stop = should_stop
        self._listeners, self._lookup, self._probe = listeners, process_lookup, prober
        self._used = False
        self._t0 = None
        self._elapsed = None
        self._stop_reason = None
        self._enumeration = "failed"
        self._counts = dict(listeners_found=0, port_filtered=0, policy_skipped=0, targets_planned=0, targets_probed=0,
                            records=0, handshakes_completed=0)
        self._truncated = False
        self._by_outcome: dict[str, int] = {}
        self._errors: list[dict] = []
        self._errors_total = 0

    @property
    def summary(self) -> dict:
        elapsed = self._elapsed if self._elapsed is not None else (self._clock() - self._t0 if self._t0 is not None else 0.0)
        return {
            "stop_reason": self._stop_reason, "complete": self._stop_reason == "completed",
            "enumeration": self._enumeration, **self._counts, "targets_truncated": self._truncated,
            "records_by_outcome": dict(self._by_outcome), "errors": [dict(e) for e in self._errors],
            "errors_total": self._errors_total, "elapsed_seconds": round(elapsed, 3),
        }

    def _error(self, kind: str, code: str) -> None:
        self._errors_total += 1
        if len(self._errors) < MAX_LISTED_ERRORS:
            self._errors.append({"kind": kind, "code": code})

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

    def records(self):
        """Yield one record per probe attempt. A TlsScan can be consumed once."""
        if self._used:
            raise RuntimeError("a TlsScan can be consumed only once")
        self._used = True
        self._t0 = self._clock()
        try:
            try:
                table = self._listeners()
            except EnumerationError as failure:
                self._error("enumerate", failure.code)
                self._stop_reason = "enumeration_failed"
                return
            self._enumeration = "ok"
            ports = None if self._cfg.ports is None else frozenset(self._cfg.ports)
            plan = build_plan(table, max_targets=self._cfg.max_targets, ports=ports)
            self._truncated = plan.truncated
            self._counts.update(listeners_found=plan.listeners_found, port_filtered=plan.port_filtered,
                                policy_skipped=plan.policy_skipped, targets_planned=len(plan.targets))
            timeouts = Timeouts(self._cfg.connect_timeout_seconds, self._cfg.handshake_timeout_seconds)
            for target in plan.targets:
                if self._halt():
                    return
                self._counts["targets_probed"] += 1
                try:
                    owner = attribution(target.pid, target.ambiguous_owner, self._lookup)
                except Exception:                                    # noqa: BLE001 - attribution is best effort
                    owner = ("unavailable", None)
                try:
                    record = self._probe(target, timeouts, now=self._now, attribution=owner)
                except ProbeAborted as aborted:
                    self._error("probe", aborted.code)
                    continue
                except Exception:                                    # noqa: BLE001 - one bad target must not end the scan
                    self._error("probe", "probe_internal_error")
                    continue
                self._counts["records"] += 1
                outcome = record["handshake_outcome"]
                self._by_outcome[outcome] = self._by_outcome.get(outcome, 0) + 1
                if outcome == "completed":
                    self._counts["handshakes_completed"] += 1
                yield record
            if not self._stop_reason:
                self._stop_reason = "target_limit" if plan.truncated else "completed"
        except GeneratorExit:
            self._stop_reason = self._stop_reason or "cancelled"
            raise
        finally:
            self._stop_reason = self._stop_reason or "completed"
            self._elapsed = self._clock() - self._t0
