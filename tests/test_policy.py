"""Unit tests for the policy engine, PII redaction, and identity provider."""
from pathlib import Path

from app.identity import Identity, StaticIdentityProvider
from app.pipeline.pii import PIIEntity, redact
from app.pipeline.policy import PolicyEngine

POLICIES_DIR = Path(__file__).resolve().parents[1] / "policies"


class FakePIIDetector:
    """Returns canned entities; None mimics an unavailable model."""

    def __init__(self, entities: list[PIIEntity] | None):
        self._entities = entities
        self.load_error = "test" if entities is None else None

    @property
    def available(self) -> bool:
        return self._entities is not None

    def detect(self, text: str) -> list[PIIEntity] | None:
        return self._entities


def make_engine() -> PolicyEngine:
    return PolicyEngine(policies_dir=POLICIES_DIR)


NO_PII = FakePIIDetector([])


class TestCapabilities:
    def test_allowed_capability_passes(self):
        d = make_engine().evaluate(
            "support-bot", "hello", ["web_search"], ["default"], NO_PII
        )
        assert d.verdict is None
        assert d.capability_violations == []

    def test_blocked_capability_blocks(self):
        d = make_engine().evaluate(
            "support-bot", "hello", ["code_execution"], ["default"], NO_PII
        )
        assert d.verdict == "block"
        assert d.blocked_by == "capabilities"
        assert d.capability_violations == ["code_execution"]

    def test_unlisted_capability_blocks(self):
        d = make_engine().evaluate(
            "support-bot", "hello", ["send_email"], ["default"], NO_PII
        )
        assert d.verdict == "block"

    def test_admin_role_unlocks_code_execution(self):
        d = make_engine().evaluate(
            "support-bot", "hello", ["code_execution"], ["admin"], NO_PII
        )
        assert d.verdict is None

    def test_admin_still_denied_file_write(self):
        d = make_engine().evaluate(
            "support-bot", "hello", ["file_write"], ["admin"], NO_PII
        )
        assert d.verdict == "block"

    def test_no_capabilities_requested_passes(self):
        d = make_engine().evaluate("support-bot", "hello", [], ["default"], NO_PII)
        assert d.verdict is None


class TestTopics:
    def test_blocked_topic_keyword(self):
        d = make_engine().evaluate(
            "support-bot", "What dosage of ibuprofen is safe?", [], ["default"], NO_PII
        )
        assert d.verdict == "block"
        assert d.blocked_by == "topics"
        assert "medical_advice" in d.topic_matches

    def test_keyword_match_is_case_insensitive(self):
        d = make_engine().evaluate(
            "support-bot", "Tell me about ACME Corp pricing", [], ["default"], NO_PII
        )
        assert d.verdict == "block"
        assert "competitors" in d.topic_matches

    def test_clean_topic_passes(self):
        d = make_engine().evaluate(
            "support-bot", "How do I reset my password?", [], ["default"], NO_PII
        )
        assert d.topic_matches == []


class TestPII:
    def test_redact_action(self):
        text = "Contact john@example.com or call 555-1234"
        detector = FakePIIDetector([
            PIIEntity("EMAIL", "john@example.com", 8, 24),
            PIIEntity("PHONE", "555-1234", 33, 41),
        ])
        d = make_engine().evaluate("support-bot", text, [], ["default"], detector)
        assert d.verdict is None
        assert d.pii_found == ["EMAIL", "PHONE"]
        assert "[EMAIL_1]" in d.redacted_prompt
        assert "[PHONE_1]" in d.redacted_prompt
        assert "john@example.com" not in d.redacted_prompt

    def test_no_pii_found(self):
        d = make_engine().evaluate("support-bot", "hello world", [], ["default"], NO_PII)
        assert d.pii_found == []
        assert d.redacted_prompt is None

    def test_detector_unavailable_forces_review(self):
        d = make_engine().evaluate(
            "support-bot", "hello", [], ["default"], FakePIIDetector(None)
        )
        assert d.verdict == "review"
        assert "unavailable" in d.note

    def test_entity_filter_respected(self):
        # USERNAME is not in support-bot's entities list — must be ignored.
        detector = FakePIIDetector([PIIEntity("USERNAME", "jdoe", 0, 4)])
        d = make_engine().evaluate("support-bot", "jdoe here", [], ["default"], detector)
        assert d.pii_found == []
        assert d.redacted_prompt is None


class TestStrictDefault:
    def test_unknown_app_gets_strict_default(self):
        d = make_engine().evaluate(
            "no-such-app", "hello", ["web_search"], ["default"], NO_PII
        )
        assert d.verdict == "block"
        assert "strict default" in d.note

    def test_unknown_app_no_capabilities_passes(self):
        d = make_engine().evaluate("no-such-app", "hello", [], ["default"], NO_PII)
        assert d.verdict is None


class TestRedactFunction:
    def test_same_value_same_placeholder(self):
        text = "a@b.com wrote to a@b.com"
        entities = [
            PIIEntity("EMAIL", "a@b.com", 0, 7),
            PIIEntity("EMAIL", "a@b.com", 17, 24),
        ]
        redacted, found = redact(text, entities)
        assert redacted == "[EMAIL_1] wrote to [EMAIL_1]"
        assert found == ["EMAIL"]

    def test_different_values_numbered(self):
        text = "a@b.com and c@d.com"
        entities = [
            PIIEntity("EMAIL", "a@b.com", 0, 7),
            PIIEntity("EMAIL", "c@d.com", 12, 19),
        ]
        redacted, _ = redact(text, entities)
        assert redacted == "[EMAIL_1] and [EMAIL_2]"


class TestIdentity:
    def test_unknown_user_gets_default_role(self):
        provider = StaticIdentityProvider(identities_path=Path("/nonexistent"))
        identity = provider.resolve("anyone")
        assert identity.roles == ["default"]

    def test_known_user_from_file(self, tmp_path):
        f = tmp_path / "identities.yaml"
        f.write_text("users:\n  u1:\n    roles: [admin]\n")
        provider = StaticIdentityProvider(identities_path=f)
        assert provider.resolve("u1").roles == ["admin"]
        assert provider.resolve("u2").roles == ["default"]


class TestEntityType:
    """_entity_type retypes refined spans by what the text actually is."""

    def test_email_retyped_regardless_of_model_label(self):
        from app.pipeline.pii import _entity_type

        assert _entity_type("USERNAME", "john.smith@example.com") == "EMAIL"
        assert _entity_type("GIVENNAME", "a@b.co") == "EMAIL"

    def test_non_email_keeps_canonical_mapping(self):
        from app.pipeline.pii import _entity_type

        assert _entity_type("USERNAME", "john.smith") == "USERNAME"
        assert _entity_type("PER", "John Smith") == "PERSON"
        assert _entity_type("TELEPHONENUM", "555-0100") == "PHONE"
