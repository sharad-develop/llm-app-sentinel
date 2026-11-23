"""POST /v1/context/check — vet untrusted content before the model reads it (LLM01)."""
import time
import uuid

from fastapi import APIRouter, Request

from app.audit import audit_log, prompt_hash
from app.models.request import ContextCheckRequest
from app.models.response import ContextCheckResponse
from app.pipeline.context_guard import analyze_context

router = APIRouter()


@router.post(
    "/context/check", response_model=ContextCheckResponse, response_model_exclude_none=True
)
def check_context(body: ContextCheckRequest, request: Request) -> ContextCheckResponse:
    start = time.perf_counter()
    request_id = str(uuid.uuid4())
    ctx = body.context
    hashed = prompt_hash(body.content)
    result = analyze_context(
        body.content,
        source=body.source,
        rule_engine=request.app.state.context_rule_engine,
        classifier=request.app.state.classifier,
        t_medium=body.options.thresholds.medium,
        t_high=body.options.thresholds.high,
        request_id=request_id,
        hashed=hashed,
        start=start,
    )
    audit_log(
        request_id, f"context_check:{body.source}" if body.source else "context_check",
        result.verdict, hashed,
        application_id=ctx.application_id if ctx else None,
        user_id=ctx.user_id if ctx else None,
        session_id=ctx.session_id if ctx else None,
        risk_score=result.risk_score,
        violations=(
            (result.pipeline.rule_checks.violations if result.pipeline.rule_checks else [])
            + (result.pipeline.hidden_content.signals if result.pipeline.hidden_content else [])
        ) or None,
    )
    return result
