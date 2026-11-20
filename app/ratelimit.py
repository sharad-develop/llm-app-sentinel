"""Sliding-window rate limiter (OWASP LLM10 — unbounded consumption).

In-process and per-instance: each worker/replica keeps its own counters, so
the effective cluster-wide limit is ``limit x replicas``. For strict global
limits enforce at the gateway; this is a safety net against runaway callers.
"""
import threading
import time
from collections import deque

from app.config import settings


class RateLimitExceeded(Exception):
    """Raised when a caller exceeds its request budget."""

    def __init__(self, key: str, retry_after: int) -> None:
        self.key = key
        self.retry_after = retry_after
        super().__init__(f"rate limit exceeded for {key!r}; retry in {retry_after}s")


class RateLimiter:
    """Allow at most ``limit`` calls per ``window`` seconds for each key.

    ``limit <= 0`` disables limiting. Tracked keys are bounded by
    ``max_keys`` so rotating identifiers cannot grow memory without bound.
    """

    def __init__(
        self,
        limit: int | None = None,
        window: float | None = None,
        max_keys: int | None = None,
        clock=time.monotonic,
    ) -> None:
        self.limit = settings.rate_limit_requests if limit is None else limit
        self.window = settings.rate_limit_window_seconds if window is None else window
        self.max_keys = settings.rate_limit_max_keys if max_keys is None else max_keys
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.limit > 0

    def check(self, key: str) -> None:
        """Record a hit for ``key``; raise ``RateLimitExceeded`` if over budget."""
        if not self.enabled:
            return
        now = self._clock()
        cutoff = now - self.window
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self.max_keys:
                    self._sweep(cutoff)
                    if len(self._hits) >= self.max_keys:
                        # Still full of live keys: fail closed rather than
                        # letting an attacker evict legitimate counters.
                        raise RateLimitExceeded(key, max(1, int(self.window)))
                hits = self._hits[key] = deque()
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                retry = int(hits[0] + self.window - now) + 1
                raise RateLimitExceeded(key, max(1, retry))
            hits.append(now)

    def _sweep(self, cutoff: float) -> None:
        for k in [k for k, h in self._hits.items() if not h or h[-1] <= cutoff]:
            del self._hits[k]


def rate_limit_key(
    user_id: str | None, application_id: str | None, fallback: str = "anonymous"
) -> str:
    if user_id:
        return f"user:{user_id}"
    if application_id:
        return f"app:{application_id}"
    return fallback
