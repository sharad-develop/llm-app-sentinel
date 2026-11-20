"""Resource-limit tests (OWASP LLM10): rate limiting, body size, chunk cap."""
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.pipeline.classifier import PromptGuardClassifier
from app.ratelimit import RateLimiter, RateLimitExceeded
from sentinel import Guard


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class TestRateLimiter:
    def test_disabled_by_default(self):
        rl = RateLimiter(limit=0)
        for _ in range(1000):
            rl.check("k")

    def test_blocks_over_limit_then_recovers(self):
        clock = FakeClock()
        rl = RateLimiter(limit=2, window=10, clock=clock)
        rl.check("k")
        rl.check("k")
        with pytest.raises(RateLimitExceeded) as exc:
            rl.check("k")
        assert exc.value.retry_after >= 1
        clock.t = 11
        rl.check("k")

    def test_keys_are_independent(self):
        rl = RateLimiter(limit=1, window=10, clock=FakeClock())
        rl.check("a")
        rl.check("b")
        with pytest.raises(RateLimitExceeded):
            rl.check("a")

    def test_key_table_is_bounded_and_fails_closed(self):
        rl = RateLimiter(limit=5, window=10, max_keys=2, clock=FakeClock())
        rl.check("a")
        rl.check("b")
        with pytest.raises(RateLimitExceeded):
            rl.check("c")

    def test_expired_keys_are_swept(self):
        clock = FakeClock()
        rl = RateLimiter(limit=5, window=10, max_keys=2, clock=clock)
        rl.check("a")
        rl.check("b")
        clock.t = 20
        rl.check("c")


class TestSdkRateLimit:
    def test_guard_enforces_limit_per_user(self):
        g = Guard()
        g._rate_limiter = RateLimiter(limit=1, window=60)
        g.check_input("hello there", user_id="u1")
        with pytest.raises(RateLimitExceeded):
            g.check_input("hello again", user_id="u1")
        g.check_input("hello there", user_id="u2")

    def test_constructor_args(self):
        g = Guard(rate_limit=1, rate_limit_window=60)
        g.check_input("hello there", user_id="u1")
        with pytest.raises(RateLimitExceeded):
            g.check_input("hello again", user_id="u1")

    def test_output_shares_budget(self):
        g = Guard()
        g._rate_limiter = RateLimiter(limit=1, window=60)
        g.check_output("fine response", user_id="u1")
        with pytest.raises(RateLimitExceeded):
            g.check_output("fine response", user_id="u1")


class TestRestLimits:
    def test_429_with_retry_after(self):
        with TestClient(app) as c:
            app.state.rate_limiter = RateLimiter(limit=1, window=60)
            body = {"prompt": "hello", "context": {"user_id": "u1"}}
            assert c.post("/v1/input/analyze", json=body).status_code == 200
            r = c.post("/v1/input/analyze", json=body)
            assert r.status_code == 429
            assert int(r.headers["Retry-After"]) >= 1

    def test_output_endpoint_rate_limited(self):
        with TestClient(app) as c:
            app.state.rate_limiter = RateLimiter(limit=1, window=60)
            body = {"output": "hello"}
            assert c.post("/v1/output/analyze", json=body).status_code == 200
            assert c.post("/v1/output/analyze", json=body).status_code == 429

    def test_oversized_body_413(self, monkeypatch):
        monkeypatch.setattr(settings, "max_request_bytes", 100)
        with TestClient(app) as c:
            r = c.post("/v1/input/analyze", json={"prompt": "x" * 500})
            assert r.status_code == 413

    def test_missing_content_length_411(self):
        with TestClient(app) as c:
            r = c.post(
                "/v1/input/analyze",
                content=iter([b'{"prompt":"hi"}']),
                headers={"Content-Type": "application/json"},
            )
            assert r.status_code == 411

    def test_healthz_unaffected(self):
        with TestClient(app) as c:
            assert c.get("/healthz").status_code == 200


class TestClassifierChunkCap:
    def test_too_many_chunks_not_scored(self, monkeypatch):
        import sys
        import types

        # score() imports torch lazily; a stub keeps this test torch-free.
        monkeypatch.setitem(sys.modules, "torch", types.ModuleType("torch"))
        monkeypatch.setattr(settings, "classifier_max_chunks", 2)

        class Ids:
            shape = (5, 8)

        clf = PromptGuardClassifier()
        clf.enabled = True
        clf._model = object()
        clf._tokenizer = lambda *a, **k: {"input_ids": Ids(), "attention_mask": Ids()}
        res = clf.score("some text")
        assert res.ran is False
        assert res.note.startswith("input_too_long")
