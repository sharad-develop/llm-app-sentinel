"""Shared Hugging Face loading policy.

Keeping cache fallback and model-repository safety options in one place makes
it harder for a new pipeline stage to accidentally omit revision pinning or
enable execution of code shipped by a model repository.
"""
from typing import Any

from sentinel.pipeline.model_pin import resolve_revision


def load_pretrained(
    loader: Any,
    model_name: str,
    revision: str | None,
    **kwargs: Any,
) -> Any:
    """Load a Transformers object from cache first, then the Hub.

    ``loader`` is one of the Transformers ``Auto*`` classes. All callers get
    the same explicit remote-code policy and revision handling.
    """
    resolved = resolve_revision(model_name, revision)
    options = {
        "revision": resolved,
        "trust_remote_code": False,
        **kwargs,
    }
    try:
        return loader.from_pretrained(model_name, local_files_only=True, **options)
    except OSError:
        return loader.from_pretrained(model_name, **options)
