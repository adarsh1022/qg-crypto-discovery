"""Service settings: one frozen, validated object. No environment lookups, no globals."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .run_state import Timeouts

DEFAULT_ALLOWED_HOSTS = ("127.0.0.1", "localhost", "[::1]")
MAX_QUERY_BUDGET_S = 300


@dataclass(frozen=True)
class Settings:
    db_path: str | Path
    data_origin: str = "agent"                          # 'agent' or 'sample' (a database never mixes the two)
    timeouts: Timeouts = field(default_factory=Timeouts)
    heartbeat_interval_s: float = 15.0                  # advertised to the agent; must be well below the timeout
    max_batch_items: int = 500
    max_body_bytes: int = 2 * 1024 * 1024
    sweep_interval_s: float | None = 15.0               # background expiry of stale runs; None disables the task
    allowed_hosts: tuple[str, ...] = DEFAULT_ALLOWED_HOSTS
    allowed_origins: tuple[str, ...] = ()               # extra browser origins (e.g. a UI dev server) beyond loopback
    query_budget_s: float = 5.0                         # time one report request may spend (SQL and Python together)

    def __post_init__(self):
        if (isinstance(self.query_budget_s, bool) or not isinstance(self.query_budget_s, (int, float))
                or not 0 < self.query_budget_s <= MAX_QUERY_BUDGET_S):
            raise ValueError(f"query_budget_s must be a number above 0 and at most {MAX_QUERY_BUDGET_S}")
        if str(self.db_path) == ":memory:":
            raise ValueError("an in-memory database cannot be shared between requests; use a file")
        for name in ("heartbeat_interval_s",):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value < float("inf"):
                raise ValueError(f"{name} must be a positive finite number")
        if self.heartbeat_interval_s >= self.timeouts.heartbeat_s:
            raise ValueError("heartbeat_interval_s must be smaller than the heartbeat timeout")
        for name in ("max_batch_items", "max_body_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.sweep_interval_s is not None and (isinstance(self.sweep_interval_s, bool) or
                                                  not isinstance(self.sweep_interval_s, (int, float)) or
                                                  not 0 < self.sweep_interval_s < float("inf")):
            raise ValueError("sweep_interval_s must be a positive finite number or None")
        if not self.allowed_hosts or not all(isinstance(h, str) and h for h in self.allowed_hosts):
            raise ValueError("allowed_hosts must be a non-empty tuple of host names")
        object.__setattr__(self, "allowed_hosts", tuple(h.lower() for h in self.allowed_hosts))
        object.__setattr__(self, "allowed_origins", tuple(o.lower().rstrip("/") for o in self.allowed_origins))
