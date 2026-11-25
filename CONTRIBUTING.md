# Contributing to llm-sentinel

Thanks for helping improve llm-sentinel. Contributions should preserve the
project's fail-safe behavior: unavailable or unparseable security checks must
not silently become an `allow` verdict.

## Before you start

- Check existing issues and pull requests for related work.
- For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of
  opening a public issue.
- Keep changes focused and explain behavior changes in the pull request.

## Development setup

The project requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Install the optional ML dependencies only when working on model-backed
inference:

```bash
python -m pip install -e ".[ml]"
```

The test suite disables model loading through `tests/conftest.py`, so ordinary
unit and integration tests do not require model downloads.

## Checks before submitting

Run the automated checks from the repository root:

```bash
python -m pytest -q
python -m compileall -q sentinel tests examples scripts
git diff --check
```

The REST API and its end-to-end scripts live in the separate llm-sentry-gateway project.

## Code guidelines

- Keep deterministic checks cheap and place them before model-backed stages.
- Keep input and output behavior consistent between the SDK and the gateway (which only wraps the SDK — put logic in `sentinel/`, not in the gateway).
- Do not log prompt, output, secret, or PII content. Audit records should use
  hashes or explicitly approved identifiers only.
- Add regression tests for security-sensitive behavior, including both the
  blocking path and fail-safe behavior when a dependency is unavailable.
- Update the README and configuration documentation when public behavior or
  environment variables change.

## Pull requests

A pull request should include:

- a clear description of the problem and the chosen approach;
- tests covering new behavior and regressions;
- documentation for public API or configuration changes;
- notes about model, policy, performance, or compatibility implications.

Keep commits reviewable and avoid committing generated caches, virtual
environments, model weights, credentials, or `*.egg-info` build artifacts.
