"""POST /v1/output/analyze — the output guard pipeline.

Vets a MODEL response before it is returned to the end user:

  1. schema validation   (Pydantic — length, control chars, unknown fields)
  2. normalization       (same canonicalization as the input pipeline)
  3. rule checks         (rules/output.yaml — prompt leakage, secrets)
     leakage check       (optional: real system prompt / canary tokens)
  4. policy              (topics + PII per application; no capabilities)
  5. safety classifier   (Llama Guard 3 — safe/unsafe + hazard categories)

Policy runs BEFORE the safety classifier so Llama Guard judges the
sanitized text — what would actually be shown to the end user. Otherwise
its privacy category (S7) blocks outputs whose PII the application's
policy explicitly chose to redact.

Verdicts are binary at the safety stage (Llama Guard generates a label,
not a score): safe → allow, unsafe → block, unavailable → review.
"""
import time
import uuid

from fastapi import APIRouter, Request

from app.ratelimit import rate_limit_key
from app.audit import audit_log, prompt_hash, utc_now
from app.models.request import OutputAnalyzeRequest
from app.models.response import (
    LeakageStageResult,
    NormalizationStageResult,
    OutputAnalyzeResponse,
    OutputPipelineDetail,
    PIIPolicyResult,
    PolicyStageResult,
    ResponseMeta,
    RuleChecksStageResult,
    SafetyStageResult,
)
from app.pipeline.leakage import run_leak_checks
from app.pipeline.normalization import normalize

router = APIRouter()


@router.post(
    "/output/analyze",
    response_model=OutputAnalyzeResponse,
    response_model_exclude_none=True,
)
def analyze_output(body: OutputAnalyzeRequest, request: Request) -> OutputAnalyzeResponse:
    start = time.perf_counter()
    request_id = str(uuid.uuid4())
    app_id = body.context.application_id if body.context else None
    user_id = body.context.user_id if body.context else None
    session_id = body.context.session_id if body.context else None
    # Before any expensive stage (LLM10). Raises RateLimitExceeded -> HTTP 429.
    request.app.state.rate_limiter.check(rate_limit_key(
        user_id, app_id, f"ip:{request.client.host if request.client else 'unknown'}"
    ))
    hashed = prompt_hash(body.output)

    pipeline = OutputPipelineDetail()

    # Stage 2 — normalization (stage 1, request validation, already ran via Pydantic)
    norm = normalize(body.output)
    pipeline.normalization = NormalizationStageResult(applied=norm.applied)

    # Stage 3 — rule checks (output pack: leakage + secrets)
    rule_result = request.app.state.output_rule_engine.check(norm.text)
    pipeline.rule_checks = RuleChecksStageResult(
        passed=rule_result.passed, violations=rule_result.violations
    )
    if not rule_result.passed:
        audit_log(
            request_id, "output_rule_checks", "block", hashed,
            application_id=app_id, user_id=user_id, session_id=session_id,
            violations=rule_result.violations,
        )
        return _respond(
            request_id, "block", pipeline, hashed, start,
            blocked_at="rule_checks",
        )

    # Stage 3b — system-prompt leakage (LLM07); runs only when the caller
    # supplies the system prompt and/or canaries.
    leak = run_leak_checks(
        norm.text, body.system_prompt, body.canaries,
        detector=request.app.state.semantic_leak, semantic=body.semantic_leak,
    )
    if leak.ran:
        pipeline.leakage = LeakageStageResult(
            ran=True, violations=leak.violations,
            semantic_similarity=leak.semantic_similarity, note=leak.note,
        )
        if leak.leaked:
            audit_log(
                request_id, "output_leakage", "block", hashed,
                application_id=app_id, user_id=user_id, session_id=session_id,
                violations=leak.violations,
            )
            return _respond(
                request_id, "block", pipeline, hashed, start,
                blocked_at="leakage",
            )

    # Stage 4 — policy (topics + PII; only when the caller identifies an app).
    # Runs before the safety classifier so PII the policy redacts doesn't
    # trip Llama Guard's privacy category on text that won't be shown.
    # Fail safe: semantic check was wanted but couldn't run → never allow outright.
    verdict = "review" if leak.needs_review else "allow"
    sanitized = norm.text
    pii_handled_by_policy = False
    if app_id is not None:
        decision = request.app.state.policy_engine.evaluate_output(
            application_id=app_id,
            text=norm.text,
            pii_detector=request.app.state.pii_detector,
        )
        pipeline.policy = PolicyStageResult(
            evaluated=True,
            topic_matches=decision.topic_matches,
            pii=PIIPolicyResult(found=decision.pii_found, action=decision.pii_action)
            if decision.pii_action
            else None,
            note=decision.note,
        )
        pii_handled_by_policy = decision.pii_action is not None
        if decision.redacted_prompt is not None:
            sanitized = decision.redacted_prompt
        if decision.verdict == "block":
            audit_log(
                request_id, "output_policy", "block", hashed,
                application_id=app_id, user_id=user_id, session_id=session_id,
                violations=decision.topic_matches
                + ([f"pii:{t}" for t in decision.pii_found] if decision.blocked_by == "pii" else []),
            )
            return _respond(
                request_id, "block", pipeline, hashed, start,
                blocked_at="policy",
            )
        if decision.verdict == "review":
            verdict = "review"
        audit_log(
            request_id, "output_policy", verdict, hashed,
            application_id=app_id, user_id=user_id, session_id=session_id,
        )

    # Stage 5 — Llama Guard safety classifier, on the sanitized text.
    # When the application's policy declared PII handling, it owns privacy:
    # S7 is excluded for this request (Llama Guard flags even redacted
    # placeholders as privacy-sensitive). The other categories still apply.
    safety = request.app.state.safety_classifier
    result = safety.classify(
        sanitized,
        prompt=body.prompt,
        extra_excluded_categories=["S7"] if pii_handled_by_policy else None,
    )
    pipeline.safety = SafetyStageResult(
        ran=result.ran, safe=result.safe, categories=result.categories,
        model=result.model, note=result.note,
    )
    if result.ran and result.safe is False:
        audit_log(
            request_id, "safety", "block", hashed,
            application_id=app_id, user_id=user_id, session_id=session_id,
            violations=result.categories,
        )
        return _respond(
            request_id, "block", pipeline, hashed, start,
            blocked_at="safety", safety_categories=result.categories,
        )
    # Fail safe: no safety verdict → never allow outright.
    if not result.ran:
        verdict = "review"
    audit_log(
        request_id, "safety", verdict, hashed,
        application_id=app_id, user_id=user_id, session_id=session_id,
    )

    return _respond(
        request_id, verdict, pipeline, hashed, start,
        sanitized_output=sanitized,
    )


def _respond(
    request_id: str,
    verdict: str,
    pipeline: OutputPipelineDetail,
    hashed: str,
    start: float,
    blocked_at: str | None = None,
    safety_categories: list[str] | None = None,
    sanitized_output: str | None = None,
) -> OutputAnalyzeResponse:
    return OutputAnalyzeResponse(
        request_id=request_id,
        verdict=verdict,
        blocked_at=blocked_at,
        safety_categories=safety_categories or [],
        sanitized_output=sanitized_output,
        output_hash=hashed,
        pipeline=pipeline,
        meta=ResponseMeta(
            latency_ms=int((time.perf_counter() - start) * 1000),
            timestamp=utc_now(),
        ),
    )
