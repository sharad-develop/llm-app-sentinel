---
name: preflight
description: Run every check that CONTRIBUTING.md and CI require before a PR or commit (tests, compileall, whitespace, bandit, semgrep, pip-audit) and summarize the failures. Use when the user says preflight, asks to check before committing or pushing, or asks whether the branch is ready for a PR.
---

# Preflight

Run these from the repo root with the venv active, and keep going after a failure so the report
covers everything:

```bash
python -m pytest -q
python -m compileall -q sentinel tests examples scripts
git diff --check
bandit -c pyproject.toml -r sentinel scripts
semgrep scan --config p/python --config p/owasp-top-ten --error --quiet sentinel scripts
pip-audit --strict
```

If bandit, semgrep or pip-audit isn't installed, say so and suggest
`python -m pip install -e ".[security]"`. Don't install it without asking.

Then check the diff (`git diff main...HEAD --stat` plus the working tree):
- Did public API or `SENTINEL_*` settings change without a README update?
- Did coverage change without an `OWASP_MAPPING.md` update?
- Were `rules/` edited instead of `sentinel/rules/`?
- Are any `venv/`, `build/`, `*.egg-info`, `.env` or `identities.yaml` files staged?

Report a short pass/fail table, then the details of each failure. Don't fix anything unless the
user asks.
