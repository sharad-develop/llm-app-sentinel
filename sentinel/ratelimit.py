"""Sliding-window rate limiter and token budget (OWASP LLM10 — unbounded
consumption).

``RateLimiter`` caps calls per window; with ``cost`` per call (estimated
tokens) and ``exc=TokenBudgetExceeded`` it is the per-caller token budget.

In-process and per-instance: each worker/replica keeps its own counters, so
the effective cluster-wide limit is ``limit x replicas``. For strict global
limits enforce at the gateway; this is a safety net against runaway callers.
"""
import threading
import time
from collections import deque

from sentinel.config import settings


class RateLimitExceeded(Exception):
    """Raised when a caller exceeds its request budget."""

    def __init__(self, key: str, retry_after: int) -> None:
        self.key = key
        self.retry_after = retry_after
        super().__init__(f"rate limit exceeded for {key!r}; retry in {retry_after}s")


class TokenBudgetExceeded(RateLimitExceeded):
    """Raised when a caller exceeds its token budget for the window."""

    def __init__(self, key: str, retry_after: int) -> None:
        super().__init__(key, retry_after)
        self.args = (f"token budget exceeded for {key!r}; retry in {retry_after}s",)


def estimate_tokens(text: str) -> int:
    """Cheap, dependency-free token estimate (no tokenizer needed).

    ASCII text averages ~``chars_per_token`` characters per token; every
    non-ASCII character (CJK, emoji, ...) is counted as one token, which errs
    on the high side — a budget should over-count rather than under-count.
    """
    ascii_chars = sum(1 for c in text if c < "\x80")
    other = len(text) - ascii_chars
    return max(1, int(ascii_chars / settings.chars_per_token + 0.999) + other)


class RateLimiter:
    """Allow at most ``limit`` units per ``window`` seconds for each key.

    Each call costs ``cost`` units (default 1, i.e. a request count).

    ``limit <= 0`` disables limiting. Tracked keys are bounded by
    ``max_keys`` so rotating identifiers cannot grow memory without bound.
    """

    def __init__(
        self,
        limit: int | None = None,
        window: float | None = None,
        max_keys: int | None = None,
        clock=time.monotonic,
        exc: type[RateLimitExceeded] = RateLimitExceeded,
    ) -> None:
        self.limit = settings.rate_limit_requests if limit is None else limit
        self.window = settings.rate_limit_window_seconds if window is None else window
        self.max_keys = settings.rate_limit_max_keys if max_keys is None else max_keys
        self._clock = clock
        self._exc = exc
        self._hits: dict[str, deque[tuple[float, int]]] = {}
        self._totals: dict[str, int] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.limit > 0

    def check(self, key: str, cost: int = 1) -> None:
        """Charge ``cost`` to ``key``; raise ``RateLimitExceeded`` if over budget."""
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
                        raise self._exc(key, max(1, int(self.window)))
                hits = self._hits[key] = deque()
                self._totals[key] = 0
            while hits and hits[0][0] <= cutoff:
                self._totals[key] -= hits.popleft()[1]
            if self._totals[key] + cost > self.limit:
                # Time until enough of the oldest charges expire to fit `cost`
                # (a single charge larger than the whole limit waits a window).
                need, freed, retry = self._totals[key] + cost - self.limit, 0, self.window
                for ts, c in hits:
                    freed += c
                    if freed >= need:
                        retry = ts + self.window - now
                        break
                raise self._exc(key, max(1, int(retry) + 1))
            hits.append((now, cost))
            self._totals[key] += cost

    def _sweep(self, cutoff: float) -> None:
        for k in [k for k, h in self._hits.items() if not h or h[-1][0] <= cutoff]:
            del self._hits[k]
            del self._totals[k]


def rate_limit_key(
    user_id: str | None, application_id: str | None, fallback: str = "anonymous"
) -> str:
    if user_id:
        return f"user:{user_id}"
    if application_id:
        return f"app:{application_id}"
    return fallback
