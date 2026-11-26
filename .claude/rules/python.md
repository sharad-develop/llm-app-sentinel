---
paths:
  - "**/*.py"
---

# Python conventions

Target Python 3.11+, and match the existing code in `sentinel/`.

## Style
- Use modern typing: `str | None`, `list[str]`, `dict[str, int]`. Don't use `Optional` or `List`.
- Annotate every public function. Use `Literal` for closed sets (as with `Verdict`).
- Use Pydantic models for API and response shapes, and `@dataclass` for internal results.
- Every module starts with a docstring that says which pipeline stage or concern it owns.
- Name private helpers and module constants with a leading underscore (`_validate_prompt_text`,
  `_CONTROL_CHARS`).
- Prefer `pathlib.Path` to `os.path`.

## Config and constants
- Put tunables (thresholds, limits, patterns, model names) in `sentinel/config.py` as `SENTINEL_*`
  settings, not as literals in pipeline code.
- Compile regexes once at module level, not per call.
- Load package data (rule packs) with `importlib.resources`, not paths relative to `__file__`.

## Errors and safety
- Invalid caller input raises `ValueError` with a message that **does not echo the input**.
- A bare `except:` is forbidden. Catch specific exceptions. Any broad `except Exception` in a check
  must end in `review` or `block`, never `allow` or a silent pass. Mark it with a comment that says
  why, as the existing code does: `# noqa: BLE001 - any load failure means unavailable`.
- Use `yaml.safe_load` only. Never use `pickle`, `eval`, `exec`, `shell=True`, or
  `trust_remote_code=True`.
- Shared mutable state (rate limiters, model caches) needs a `threading.Lock`.

## Logging
- Get loggers with `logging.getLogger("llm_sentinel.<module>")`. Never use `print` in `sentinel/`.
- Use lazy `%s` formatting: `logger.info("model %s", name)`, not f-strings.
- Never log prompt, output, context, secret, or PII text. Log hashes (`audit.prompt_hash`), rule
  IDs, and counts.

## Dependencies
- Core imports must stay light. Import `transformers`/`torch` lazily inside the `[ml]` code paths,
  so `pip install -e .` works without them.
- Add a new runtime dependency to `pyproject.toml` only when the stdlib can't do the job, and say
  why in the PR.

## Tests
- pytest, plain `assert`, one behavior per test, and a name that says the expectation
  (`test_unavailable_classifier_returns_review`).
- Inject fakes for models. Never download models or hit the network.
- Use `monkeypatch` for env and settings changes, never module-global mutation.
