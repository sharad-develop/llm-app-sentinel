"""prompt-citadel — FastAPI application entry point."""
import logging
import os
from contextlib import asynccontextmanager

# Quiet transformers/hub startup noise (weight-load progress bars, benign
# "UNEXPECTED keys" load reports). Must be set before transformers imports.
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")

from fastapi import FastAPI

from app.api.v1.input import router as input_router
from app.identity import StaticIdentityProvider
from app.pipeline.classifier import PromptGuardClassifier
from app.pipeline.pii import PIIDetector
from app.pipeline.policy import PolicyEngine
from app.pipeline.rules import RuleEngine

logging.basicConfig(level=logging.INFO)
# Hub/HTTP internals are noisy at INFO (one line per file probe).
for noisy in ("httpx", "huggingface_hub", "urllib3", "filelock"):
    logging.getLogger(noisy).setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.rule_engine = RuleEngine()
    app.state.classifier = PromptGuardClassifier()
    app.state.classifier.load()
    app.state.policy_engine = PolicyEngine()
    app.state.pii_detector = PIIDetector()
    app.state.pii_detector.load()
    # Swap this for a provider backed by your IAM (see app/identity.py).
    app.state.identity_provider = StaticIdentityProvider()
    yield


app = FastAPI(
    title="prompt-citadel",
    version="0.1.0",
    description="Defense-in-depth input guard for LLM applications",
    lifespan=lifespan,
)

app.include_router(input_router, prefix="/v1")


@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "classifier_loaded": app.state.classifier.available
        if hasattr(app.state, "classifier")
        else False,
    }
