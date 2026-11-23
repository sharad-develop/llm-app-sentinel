"""Pipeline stage 3 — deterministic rule checks.

Regex and heuristic checks against the normalized prompt. Any violation
blocks the request; the classifier never runs when a rule fires.

All patterns and thresholds come from app.config (env / .env file).
Rule patterns themselves live in the YAML rule pack (rules_file setting).
"""
import re
from dataclasses import dataclass, field
from importlib.resources import files as _resource_files
from pathlib import Path

import yaml

from app.config import settings

_BASE64_BLOB = re.compile(settings.base64_blob_pattern)
_HEX_BLOB = re.compile(settings.hex_blob_pattern)


@dataclass
class CompiledRule:
    id: str
    category: str
    description: str
    pattern: re.Pattern


@dataclass
class RuleCheckResult:
    passed: bool
    violations: list[str] = field(default_factory=list)


class RuleEngine:
    def __init__(
        self,
        rules_path: Path | None = None,
        categories: set[str] | None = None,
        check_encoded: bool = True,
    ):
        """``categories`` limits which ``*_patterns`` groups are loaded;
        ``check_encoded=False`` skips the encoded-blob ratio check (for
        content where base64/hex is normal, e.g. retrieved documents)."""
        # When no explicit path is given, resolve via importlib.resources so the
        # engine works correctly in both source trees and installed wheels.
        if rules_path is None:
            self._resource = _resource_files("app") / "rules" / settings.rules_file
        else:
            self._resource = rules_path
        self.max_encoded_ratio = settings.max_encoded_ratio
        self.min_blob_length = settings.min_blob_length
        self.check_encoded = check_encoded
        self.rules: list[CompiledRule] = []
        self._load(self._resource, categories)

    def add_pack(self, path: Path, categories: set[str] | None = None) -> None:
        """Load another rule pack on top of this one."""
        self._load(path, categories)

    def _load(self, resource, categories: set[str] | None = None) -> None:
        raw = yaml.safe_load(resource.read_text(encoding="utf-8"))
        # Any top-level `*_patterns` key is a rule category, so the same
        # engine serves both the input and output rule packs.
        for category in (
            k for k in raw
            if k.endswith("_patterns") and (categories is None or k in categories)
        ):
            for entry in raw.get(category, []) or []:
                self.rules.append(
                    CompiledRule(
                        id=entry["id"],
                        category=category,
                        description=entry.get("description", ""),
                        pattern=re.compile(entry["pattern"], re.IGNORECASE),
                    )
                )

    def check(self, text: str) -> RuleCheckResult:
        violations: list[str] = []

        for rule in self.rules:
            if rule.pattern.search(text):
                violations.append(rule.id)

        if self.check_encoded and self._encoded_ratio(text) > self.max_encoded_ratio:
            violations.append("excessive_encoded_content")

        return RuleCheckResult(passed=not violations, violations=violations)

    def _encoded_ratio(self, text: str) -> float:
        if not text:
            return 0.0
        encoded_chars = 0
        for pattern in (_BASE64_BLOB, _HEX_BLOB):
            for match in pattern.finditer(text):
                if len(match.group()) >= self.min_blob_length:
                    encoded_chars += len(match.group())
        return min(encoded_chars / len(text), 1.0)
