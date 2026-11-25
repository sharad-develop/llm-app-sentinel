"""Model revision pinning (OWASP LLM03 — supply chain).

A Hugging Face model id like ``meta-llama/Llama-Prompt-Guard-2-86M`` follows
the repo's ``main`` branch, so whoever controls (or compromises) the repo
controls what your guard loads. Pin each model to a commit hash with
``SENTINEL_<MODEL>_REVISION`` and set ``SENTINEL_REQUIRE_PINNED_MODELS=true``
to refuse to load anything unpinned. ``scripts/pin_models.py`` prints the
revisions currently in your local cache.
"""
import logging
import re

from sentinel.config import settings

logger = logging.getLogger("llm_sentinel.model_pin")

_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def resolve_revision(model_name: str, revision: str | None) -> str | None:
    """The ``revision=`` to pass to ``from_pretrained`` (None = repo default).

    With ``require_pinned_models`` a missing revision, or one that is not a
    full 40-hex commit hash (branches and tags are mutable), raises
    ``ValueError`` — the caller's load-failure path then reports the model
    unavailable, which the pipeline treats as ``review``, never ``allow``.
    """
    revision = (revision or "").strip() or None
    if settings.require_pinned_models and not (revision and _COMMIT.match(revision)):
        raise ValueError(
            f"model {model_name!r} must be pinned to a 40-character commit hash "
            "(SENTINEL_REQUIRE_PINNED_MODELS is set)"
        )
    if revision is None:
        logger.warning("model %s is not pinned to a revision (follows the repo default)", model_name)
    else:
        logger.info("model %s pinned to revision %s", model_name, revision)
    return revision
