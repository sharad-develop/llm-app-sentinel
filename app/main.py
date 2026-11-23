"""llm-sentinel — FastAPI application entry point."""
import logging
import os
from contextlib import asynccontextmanager
from importlib.resources import files as _resource_files
from pathlib import Path

# Quiet transformers/hub startup noise (weight-load progress bars, benign
# "UNEXPECTED keys" load reports). Must be set before transformers imports.
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")

import secrets

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from app.api.v1.context import router as context_router
from app.api.v1.input import router as input_router
from app.api.v1.output import router as output_router
from app.api.v1.tools import router as tools_router
from app.config import settings
from app.identity import StaticIdentityProvider
from app.ratelimit import RateLimiter, RateLimitExceeded
from app.pipeline.classifier import PromptGuardClassifier
from app.pipeline.context_guard import build_context_rule_engine
from app.pipeline.pii import PIIDetector
from app.pipeline.policy import PolicyEngine
from app.pipeline.rules import RuleEngine
from app.pipeline.semantic_leak import SemanticLeakDetector
from app.pipeline.safety import LlamaGuardClassifier

logging.basicConfig(level=logging.INFO)
# Hub/HTTP internals are noisy at INFO (one line per file probe).
for noisy in ("httpx", "huggingface_hub", "urllib3", "filelock"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

_logger = logging.getLogger("llm_sentinel.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.api_key:
        _logger.warning(
            "SENTINEL_API_KEY is not set — the REST API accepts requests from any caller. "
            "Set SENTINEL_API_KEY or restrict access via mTLS / network policy."
        )
    app.state.rate_limiter = RateLimiter()
    # Lazy: the embedding model loads on first use that supplies a system prompt.
    app.state.semantic_leak = SemanticLeakDetector()
    app.state.rule_engine = RuleEngine()
    app.state.context_rule_engine = build_context_rule_engine()
    app.state.classifier = PromptGuardClassifier()
    app.state.classifier.load()
    # Output guard components
    app.state.output_rule_engine = RuleEngine(
        rules_path=Path(str(_resource_files("app") / "rules" / settings.output_rules_file))
    )
    app.state.safety_classifier = LlamaGuardClassifier()
    app.state.safety_classifier.load()
    app.state.policy_engine = PolicyEngine()
    app.state.pii_detector = PIIDetector()
    app.state.pii_detector.load()
    # Swap this for a provider backed by your IAM (see app/identity.py).
    app.state.identity_provider = StaticIdentityProvider()
    yield


app = FastAPI(
    title="llm-sentinel",
    version="0.1.0",
    description="Defense-in-depth input/output guard for LLM applications",
    lifespan=lifespan,
)

@app.middleware("http")
async def api_key_middleware(request: Request, call_next) -> Response:
    """Enforce SENTINEL_API_KEY when configured.

    /healthz is exempt so load balancers and monitoring can probe without
    credentials. All other paths require a matching bearer token.
    """
    if settings.api_key and request.url.path != "/healthz":
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "Missing Authorization header"})
        token = auth.removeprefix("Bearer ")
        if not secrets.compare_digest(token, settings.api_key):
            return JSONResponse(status_code=403, content={"detail": "Invalid API key"})
    return await call_next(request)


@app.middleware("http")
async def body_size_middleware(request: Request, call_next) -> Response:
    """Reject oversized request bodies before they are read or parsed (LLM10).

    Bodies must declare Content-Length so the limit can be enforced up front.
    """
    if request.method in ("POST", "PUT", "PATCH"):
        length = request.headers.get("content-length")
        if length is None:
            return JSONResponse(status_code=411, content={"detail": "Content-Length required"})
        if not length.isdigit() or int(length) > settings.max_request_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Request body exceeds {settings.max_request_bytes} bytes"},
            )
    return await call_next(request)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded"},
        headers={"Retry-After": str(exc.retry_after)},
    )


app.include_router(input_router, prefix="/v1")
app.include_router(output_router, prefix="/v1")
app.include_router(tools_router, prefix="/v1")
app.include_router(context_router, prefix="/v1")


@app.get("/healthz")
def healthz():
    classifier_loaded = (
        app.state.classifier.available if hasattr(app.state, "classifier") else False
    )
    safety_loaded = (
        app.state.safety_classifier.available
        if hasattr(app.state, "safety_classifier")
        else False
    )
    # "ok" only when both ML classifiers are ready; otherwise "degraded" (rule
    # checks and policy still work, but classifier/safety fall back to "review").
    status = "ok" if (classifier_loaded and safety_loaded) else "degraded"
    return {
        "status": status,
        "classifier_loaded": classifier_loaded,
        "safety_loaded": safety_loaded,
    }
