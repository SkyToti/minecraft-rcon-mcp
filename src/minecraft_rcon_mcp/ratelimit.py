"""Token-bucket rate limiter, one bucket per key (server name). See docs/DESIGN.md §7."""
from __future__ import annotations

import threading
import time
from typing import Callable

__all__ = ["RateLimiter"]


class RateLimiter:
    """Allows bursts of up to `per_minute` calls per key, refilled continuously at `per_minute / 60` per second."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic) -> None:
        if isinstance(per_minute, bool) or not isinstance(per_minute, int) or per_minute < 1:
            raise ValueError("per_minute must be a positive integer")
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0  # tokens per second
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last refill time)
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        """(allowed, retry_after_seconds). An allowed call consumes one token; retry_after is 0.0 then."""
        with self._lock:
            now = self._clock()
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + max(0.0, now - last) * self.rate)
            last = max(last, now)  # a clock going backwards never earns tokens later
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, last)
                return True, 0.0
            self._buckets[key] = (tokens, last)
            return False, (1.0 - tokens) / self.rate
