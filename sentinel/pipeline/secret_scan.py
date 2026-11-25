"""Generic secret detection for model output (OWASP LLM02).

The rule packs catch secrets with a known shape (``sk-...``, ``AKIA...``,
JWTs). This module catches the rest, by two heuristics:

  * ``secret_assignment``  — a value assigned to a name that says it is a
    secret (``api_key = "..."``, ``password: ...``) and that looks random
  * ``high_entropy_token`` — a long standalone token that mixes character
    classes and has high Shannon entropy

Both are heuristics and will occasionally misfire, so the default action is
to flag for review rather than block. Placeholders (``your-api-key``,
``<token>``, ``${TOKEN}``), hex digests, UUIDs and plain words are skipped.
"""
import math
import re
from collections import Counter
from dataclasses import dataclass

SECRET_MODES = {"allow", "flag", "redact", "block"}
REDACTION = "[REDACTED_SECRET]"

_NAME = (
    r"[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|private[_-]?key|auth[_-]?key|credential)[\w.-]*"
)
# name  (: or =)  optional quote  value
_ASSIGN = re.compile(
    rf"(?i)\b{_NAME}[\"']?\s*[:=]\s*[\"']?(?P<v>[^\s\"'`,;<>(){{}}\[\]]{{12,}})"
)
_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{32,}(?![A-Za-z0-9+/_=-])")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_PLACEHOLDER = re.compile(
    r"(?i)(your|example|sample|dummy|placeholder|changeme|redacted|xxx|\*\*\*|"
    r"\.\.\.|environ|getenv|process\.env|secret_?here|key_?here|token_?here|"
    r"password|<|\$|%\(|\{\{)"
)

ASSIGN_ENTROPY = 3.2
TOKEN_ENTROPY = 4.3


@dataclass
class SecretSpan:
    kind: str  # secret_assignment | high_entropy_token
    start: int
    end: int


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _classes(s: str) -> int:
    return sum((
        any(c.islower() for c in s),
        any(c.isupper() for c in s),
        any(c.isdigit() for c in s),
        any(not c.isalnum() for c in s),
    ))


def _looks_secret(value: str, min_entropy: float, min_classes: int) -> bool:
    if _HEX.match(value) or _UUID.match(value) or _PLACEHOLDER.search(value):
        return False
    return _classes(value) >= min_classes and shannon_entropy(value) >= min_entropy


def find_secrets(text: str) -> list[SecretSpan]:
    """Spans (non-overlapping, sorted) that look like secrets."""
    spans: list[SecretSpan] = []
    for m in _ASSIGN.finditer(text):
        v = m.group("v")
        if _looks_secret(v, ASSIGN_ENTROPY, 2) and not v.lower().startswith(("http://", "https://")):
            spans.append(SecretSpan("secret_assignment", m.start("v"), m.end("v")))
    for m in _TOKEN.finditer(text):
        if any(s.start <= m.start() < s.end for s in spans):
            continue
        if _looks_secret(m.group(), TOKEN_ENTROPY, 3):
            spans.append(SecretSpan("high_entropy_token", m.start(), m.end()))
    spans.sort(key=lambda s: s.start)
    return spans


def redact_secrets(text: str, spans: list[SecretSpan]) -> str:
    for s in sorted(spans, key=lambda s: s.start, reverse=True):
        text = text[: s.start] + REDACTION + text[s.end:]
    return text
