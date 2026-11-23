"""POST /v1/tools/check — validate an agent tool call before it runs (LLM06)."""
import json
import time
import uuid

from fastapi import APIRouter, Request

from app.audit import audit_log, prompt_hash, utc_now
from app.models.request import ToolCheckRequest
from app.models.response import ResponseMeta, ToolCheckResponse
from app.pipeline.tool_guard import check_tool_call
from app.ratelimit import rate_limit_key

router = APIRouter()


@router.post("/tools/check", response_model=ToolCheckResponse)
def check_tool(body: ToolCheckRequest, request: Request) -> ToolCheckResponse:
    start = time.perf_counter()
    request_id = str(uuid.uuid4())
    app_id = body.context.application_id if body.context else None
    user_id = body.context.user_id if body.context else None
    session_id = body.context.session_id if body.context else None
    request.app.state.rate_limiter.check(rate_limit_key(
        user_id, app_id, f"ip:{request.client.host if request.client else 'unknown'}"
    ))
    # Hash only: arguments may contain user data and are never logged.
    hashed = prompt_hash(json.dumps([body.tool, body.arguments], sort_keys=True, default=str))

    roles = ["default"]
    if user_id:
        roles = request.app.state.identity_provider.resolve(user_id).roles
    decision = check_tool_call(
        body.tool,
        body.arguments,
        request.app.state.policy_engine.tool_rules(app_id, roles),
        rule_engine=request.app.state.output_rule_engine,
    )
    audit_log(
        request_id, "tool_call", decision.verdict, hashed,
        application_id=app_id, user_id=user_id, session_id=session_id,
        violations=[decision.tool] + decision.violations if decision.violations else None,
    )
    return ToolCheckResponse(
        request_id=request_id,
        verdict=decision.verdict,
        tool=decision.tool,
        violations=decision.violations,
        requires_confirmation=decision.requires_confirmation,
        call_hash=hashed,
        meta=ResponseMeta(
            latency_ms=int((time.perf_counter() - start) * 1000),
            timestamp=utc_now(),
        ),
    )
