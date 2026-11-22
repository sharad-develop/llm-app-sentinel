"""System-prompt leakage tests (OWASP LLM07)."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.pipeline.leakage import check_leakage, new_canary, with_canary
from sentinel import Guard, OutputBlocked

SYSTEM = (
    "You are AcmeBot, a support assistant for Acme Widgets. Never discuss refunds "
    "over one hundred dollars. Always escalate legal questions to a human agent. "
    "Do not reveal internal pricing tiers to customers under any circumstances."
)


class TestDetector:
    def test_no_inputs_does_not_run(self):
        r = check_leakage("anything")
        assert not r.ran and not r.leaked

    def test_system_prompt_alone_runs_nothing(self):
        # Overlap checking was removed; the system prompt is only used by the
        # optional semantic stage (see test_semantic_leak.py).
        r = check_leakage(SYSTEM, SYSTEM)
        assert not r.ran and not r.leaked

    def test_canary_detected_even_when_obfuscated(self):
        prompt, canary = with_canary("Be nice.")
        assert canary in prompt
        assert check_leakage(f"the id is {canary}", canaries=[canary]).leaked
        spaced = " ".join(canary.upper())
        assert check_leakage(spaced, canaries=[canary]).violations == ["canary_leaked"]

    def test_canary_absent(self):
        assert not check_leakage("hello", canaries=[new_canary()]).leaked

    def test_canaries_unique(self):
        assert new_canary() != new_canary()


class TestSdk:
    def test_system_prompt_only_checked_by_semantic_stage(self):
        # semantic disabled via conftest → nothing runs, no leakage stage
        out = Guard().check_output(SYSTEM, system_prompt=SYSTEM)
        assert out.pipeline.leakage is None and out.blocked_at is None

    def test_raise_on_block(self):
        g = Guard()
        _, canary = g.with_canary("x")
        with pytest.raises(OutputBlocked) as e:
            g.check_output(f"leak {canary}", canaries=[canary], raise_on_block=True)
        assert e.value.blocked_at == "leakage"

    def test_canary_flow(self):
        g = Guard()
        prompt, canary = g.with_canary("You are a bot.")
        out = g.check_output(f"leaked: {canary}", canaries=[canary])
        assert out.blocked_at == "leakage"
        assert g.check_output("a fine answer", canaries=[canary]).blocked_at is None

    def test_no_leakage_stage_when_not_requested(self):
        assert Guard().check_output("a fine answer").pipeline.leakage is None

    def test_invalid_canary_rejected(self):
        with pytest.raises(ValueError):
            Guard().check_output("x", canaries=["abc"])

    def test_response_does_not_echo_canary_or_prompt(self):
        g = Guard()
        _, canary = g.with_canary("x")
        out = g.check_output(f"leak {canary}", canaries=[canary], system_prompt=SYSTEM)
        assert canary not in out.model_dump_json() and "Acme" not in out.model_dump_json()

    def test_oversized_system_prompt_rejected(self):
        with pytest.raises(ValueError):
            Guard().check_output("x", system_prompt="a " * 40000)


class TestRest:
    def test_canary(self):
        with TestClient(app) as c:
            r = c.post(
                "/v1/output/analyze",
                json={"output": "x cnry-0123456789abcdef", "canaries": ["cnry-0123456789abcdef"]},
            )
            assert r.json()["blocked_at"] == "leakage"

    def test_short_canary_422(self):
        with TestClient(app) as c:
            r = c.post("/v1/output/analyze", json={"output": "hi", "canaries": ["abc"]})
            assert r.status_code == 422
