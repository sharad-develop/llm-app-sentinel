# llm-sentinel

In-process Python SDK that guards LLM apps: `check_input`, `check_context`, `check_output`,
`check_tool_call`. Every check returns `allow | review | block`. Coverage of the OWASP LLM Top 10
(2025) is tracked in @OWASP_MAPPING.md; model setup is in MODELS.md.

## Commands

Run from the repo root with the virtualenv active (`source venv/bin/activate`).

```bash
python -m pip install -e ".[dev]"          # dev install (add ".[ml]" only for real model work)
python -m pytest -q                        # full suite; models are disabled by tests/conftest.py
python -m pytest tests/test_tool_guard.py -q   # single file
python -m compileall -q sentinel tests examples scripts
git diff --check

# Security tooling (mirrors .github/workflows/ci.yml, needs ".[security]")
bandit -c pyproject.toml -r sentinel scripts
semgrep scan --config p/python --config p/owasp-top-ten --error --quiet sentinel scripts
pip-audit --strict
```

## Layout

- `sentinel/guard.py`: the public `Guard` API; orchestrates the pipeline stages.
- `sentinel/pipeline/`: one module per stage (normalization, rules, classifier, policy, pii,
  context_guard, leakage, semantic_leak, output_handling, sql_guard, tool_guard, secret_scan, safety,
  model_loading, model_pin).
- `sentinel/rules/*.yaml`: **the rule packs actually loaded at runtime** (shipped as package data).
  The top-level `rules/` directory is a stale copy that has diverged; edit `sentinel/rules/`.
- `sentinel/config.py`: all settings, env prefix `SENTINEL_`. New tunables go here, not as literals.
- `policies/*.yaml`: per-application policies selected by `application_id`.
- `scripts/calibrate.py` + `scripts/data/*.yaml`: threshold calibration cases.
- `scripts/pin_models.py`: resolves Hugging Face commit hashes for revision pinning.

## Non-negotiable invariants

1. **Fail closed.** A missing model, disabled classifier, parse error, or exception must produce
   `review` (or `block`), never `allow`. Every new check needs a test for the unavailable path.
2. **Never log or store content.** No prompts, outputs, secrets, or PII in logs, audit records,
   exceptions, or verdict `reason` strings. Use hashes or rule IDs.
3. **Cheap first.** Deterministic checks (normalization, regex rules) run before model-backed stages.
   A rule hit short-circuits the classifier.
4. **Logic lives in `sentinel/`.** The REST gateway is a separate project (llm-sentry-gateway) that
   only wraps the SDK.
5. **Tools are deny-by-default.** Anything not in a policy's `tools.allowed` is blocked.
6. **Models load without remote code** (`trust_remote_code=False`) and should be revision-pinnable.

## Testing conventions

- Tests inject fakes for classifier/PII/safety models; never require downloads in unit tests.
- Security changes need both the **blocking** test and the **fail-safe** test.
- Regex rules need positive cases *and* benign near-misses (to catch false positives).

## When changing behavior

- Update OWASP_MAPPING.md if coverage, mechanism, or limits change.
- Update README.md for public API or `SENTINEL_*` env var changes.
- Never commit `venv/`, `build/`, `*.egg-info/`, model weights, `.env`, or `identities.yaml`.
