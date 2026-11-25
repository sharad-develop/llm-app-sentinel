"""LLM10: per-caller token budget."""
import pytest

from sentinel.ratelimit import (
    RateLimiter, RateLimitExceeded, TokenBudgetExceeded, estimate_tokens,
)
from sentinel import Guard


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


class TestEstimate:
    def test_ascii_about_four_chars_per_token(self):
        assert estimate_tokens("a" * 400) == 100
        assert estimate_tokens("a") == 1 and estimate_tokens("") == 1

    def test_non_ascii_counts_one_each(self):
        assert estimate_tokens("你好世界") == 4
        assert estimate_tokens("ab你好") == 3


class TestWeightedLimiter:
    def test_cost_accumulates(self):
        c = Clock()
        lim = RateLimiter(limit=100, window=60, clock=c)
        lim.check("k", 60)
        lim.check("k", 40)
        with pytest.raises(RateLimitExceeded):
            lim.check("k", 1)

    def test_window_expiry_frees_budget(self):
        c = Clock()
        lim = RateLimiter(limit=100, window=60, clock=c)
        lim.check("k", 100)
        c.t = 61
        lim.check("k", 100)

    def test_retry_after_waits_only_for_enough_to_expire(self):
        c = Clock()
        lim = RateLimiter(limit=100, window=60, clock=c)
        lim.check("k", 30)
        c.t = 10
        lim.check("k", 70)
        c.t = 20
        with pytest.raises(RateLimitExceeded) as e:
            lim.check("k", 20)  # needs the first 30 to expire: at t=60
        assert e.value.retry_after == 41

    def test_single_charge_over_limit_never_fits(self):
        lim = RateLimiter(limit=100, window=60, clock=Clock())
        with pytest.raises(RateLimitExceeded) as e:
            lim.check("k", 101)
        assert e.value.retry_after == 61

    def test_keys_isolated_and_default_cost_is_one(self):
        lim = RateLimiter(limit=1, window=60, clock=Clock())
        lim.check("a")
        lim.check("b")
        with pytest.raises(RateLimitExceeded):
            lim.check("a")

    def test_subclass_and_message(self):
        lim = RateLimiter(limit=1, window=60, clock=Clock(), exc=TokenBudgetExceeded)
        with pytest.raises(RateLimitExceeded) as e:  # subclass: one except clause covers both
            lim.check("k", 5)
        assert isinstance(e.value, TokenBudgetExceeded) and "token budget" in str(e.value)

    def test_failed_charge_not_recorded(self):
        lim = RateLimiter(limit=10, window=60, clock=Clock())
        with pytest.raises(RateLimitExceeded):
            lim.check("k", 11)
        lim.check("k", 10)


class TestGuard:
    def test_off_by_default(self):
        g = Guard()
        for _ in range(3):
            g.check_input("x" * 4000, user_id="u")

    def test_input_budget(self):
        g = Guard(token_budget=300, token_budget_window=60)
        g.check_input("a" * 800, user_id="u")  # 200 tokens
        with pytest.raises(TokenBudgetExceeded):
            g.check_input("a" * 800, user_id="u")
        g.check_input("a" * 800, user_id="someone-else")

    def test_output_and_context_charge_same_budget(self):
        g = Guard(token_budget=250, token_budget_window=60)
        g.check_output("a" * 400, user_id="u")      # 100
        g.check_context("a" * 400, user_id="u")     # 100
        with pytest.raises(TokenBudgetExceeded):
            g.check_output("a" * 400, user_id="u")  # +100 > 250

    def test_context_request_rate_limited(self):
        g = Guard(rate_limit=1, rate_limit_window=60)
        g.check_context("hello there", user_id="u")
        with pytest.raises(RateLimitExceeded):
            g.check_context("hello there", user_id="u")
