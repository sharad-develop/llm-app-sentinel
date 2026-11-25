#!/usr/bin/env python
"""Print SENTINEL_*_REVISION settings for the models in your local HF cache.

    python scripts/pin_models.py            # prints `export ...` lines
    python scripts/pin_models.py >> .env    # (strip "export " for .env files)

Pins each configured model to the commit currently checked out under
``refs/main`` — review that revision first, then commit the output to your
deployment config and set SENTINEL_REQUIRE_PINNED_MODELS=true. Models that
are not cached yet are listed so you can download them first.
"""
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.config import settings  # noqa: E402

MODELS = [
    ("SENTINEL_CLASSIFIER_REVISION", settings.classifier_model),
    ("SENTINEL_SAFETY_REVISION", settings.safety_model),
    ("SENTINEL_PII_REVISION", settings.pii_model),
    ("SENTINEL_PII_NER_REVISION", settings.pii_ner_model),
    ("SENTINEL_SEMANTIC_LEAK_REVISION", settings.semantic_leak_model),
]


def hub_cache() -> Path:
    if os.environ.get("HF_HUB_CACHE"):
        return Path(os.environ["HF_HUB_CACHE"])
    return Path(os.environ.get("HF_HOME", Path.home() / ".cache" / "huggingface")) / "hub"


def cached_revision(model_id: str, cache: Path) -> str | None:
    ref = cache / ("models--" + model_id.replace("/", "--")) / "refs" / "main"
    try:
        rev = ref.read_text().strip()
    except OSError:
        return None
    return rev if re.fullmatch(r"[0-9a-f]{40}", rev) else None


def main() -> int:
    cache = hub_cache()
    missing = []
    for env, model_id in MODELS:
        if not model_id:
            continue
        rev = cached_revision(model_id, cache)
        if rev:
            print(f"export {env}={rev}  # {model_id}")
        else:
            missing.append(model_id)
    if missing:
        print(f"# not found in {cache}: {', '.join(missing)}", file=sys.stderr)
    print("export SENTINEL_REQUIRE_PINNED_MODELS=true")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
