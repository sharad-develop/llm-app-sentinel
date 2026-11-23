"""Response schema for POST /v1/input/analyze."""
from typing import Literal

from pydantic import BaseModel

Verdict = Literal["allow", "review", "block"]


class SchemaStageResult(BaseModel):
    passed: bool = True


class NormalizationStageResult(BaseModel):
    applied: list[str] = []


class RuleChecksStageResult(BaseModel):
    passed: bool
    violations: list[str] = []


class ClassifierStageResult(BaseModel):
    ran: bool
    score: float | None = None
    model: str | None = None
    note: str | None = None


class PIIPolicyResult(BaseModel):
    found: list[str] = []
    action: str | None = None


class PolicyStageResult(BaseModel):
    evaluated: bool
    capability_violations: list[str] = []
    topic_matches: list[str] = []
    pii: PIIPolicyResult | None = None
    note: str | None = None


class PipelineDetail(BaseModel):
    schema_validation: SchemaStageResult = SchemaStageResult()
    normalization: NormalizationStageResult = NormalizationStageResult()
    rule_checks: RuleChecksStageResult | None = None
    classifier: ClassifierStageResult | None = None
    policy: PolicyStageResult | None = None


class ResponseMeta(BaseModel):
    latency_ms: int
    timestamp: str


class AnalyzeResponse(BaseModel):
    request_id: str
    verdict: Verdict
    risk_score: float | None = None
    blocked_at: Literal["rule_checks", "classifier", "policy"] | None = None
    sanitized_prompt: str | None = None
    prompt_hash: str
    pipeline: PipelineDetail
    meta: ResponseMeta


# --- POST /v1/output/analyze ---


class SafetyStageResult(BaseModel):
    """Llama Guard verdict: binary safe/unsafe plus hazard categories —
    no score, unlike the input classifier."""

    ran: bool
    safe: bool | None = None
    categories: list[str] = []
    model: str | None = None
    note: str | None = None


class LeakageStageResult(BaseModel):
    ran: bool
    violations: list[str] = []
    # Fraction of system-prompt n-grams reproduced in the response.
    # Best embedding similarity (only when the semantic check ran).
    semantic_similarity: float | None = None
    note: str | None = None


class OutputHandlingStageResult(BaseModel):
    ran: bool
    # Constructs found: "image", "link", "html".
    findings: list[str] = []
    # What was done about them, e.g. "strip_image", "sanitize_html".
    actions: list[str] = []
    # SQL-injection indicator ids, e.g. "sql_destructive" (policy `sql` != allow).
    sql_indicators: list[str] = []
    note: str | None = None


class OutputPipelineDetail(BaseModel):
    # Field order mirrors execution order: policy (redaction) runs before
    # the safety classifier so Llama Guard judges the sanitized text.
    schema_validation: SchemaStageResult = SchemaStageResult()
    normalization: NormalizationStageResult = NormalizationStageResult()
    rule_checks: RuleChecksStageResult | None = None
    leakage: LeakageStageResult | None = None
    output_handling: OutputHandlingStageResult | None = None
    policy: PolicyStageResult | None = None
    safety: SafetyStageResult | None = None


class OutputAnalyzeResponse(BaseModel):
    request_id: str
    verdict: Verdict
    blocked_at: Literal["rule_checks", "leakage", "output_handling", "safety", "policy"] | None = None
    safety_categories: list[str] = []
    sanitized_output: str | None = None
    output_hash: str
    pipeline: OutputPipelineDetail
    meta: ResponseMeta


# --- POST /v1/tools/check ---


class ToolCheckResponse(BaseModel):
    request_id: str
    verdict: Verdict
    tool: str
    # Machine-readable reasons, e.g. "tool_not_allowed", "arg_path:file".
    # They name the argument, never its value.
    violations: list[str] = []
    # True when the call is valid but the policy requires a human to approve it.
    requires_confirmation: bool = False
    call_hash: str
    meta: ResponseMeta


# --- POST /v1/context/check ---


class HiddenContentStageResult(BaseModel):
    # unicode_tags | invisible_characters | css_hidden_text
    signals: list[str] = []
    # True when ASCII smuggled in Unicode tag characters was decoded and scanned.
    decoded_hidden_text: bool = False


class ContextPipelineDetail(BaseModel):
    hidden_content: HiddenContentStageResult | None = None
    normalization: NormalizationStageResult | None = None
    rule_checks: RuleChecksStageResult | None = None
    classifier: ClassifierStageResult | None = None


class ContextCheckResponse(BaseModel):
    request_id: str
    verdict: Verdict
    source: str | None = None
    blocked_at: Literal["rule_checks", "classifier"] | None = None
    risk_score: float | None = None
    # Normalized content with hidden characters removed; None when blocked.
    sanitized_content: str | None = None
    content_hash: str
    pipeline: ContextPipelineDetail
    meta: ResponseMeta
