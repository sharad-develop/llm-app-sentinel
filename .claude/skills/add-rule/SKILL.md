---
name: add-rule
description: Add or change a detection rule in an llm-sentinel rule pack (input injection, context, or output rules) with tests and documentation. Use when the user wants to detect a new attack pattern, jailbreak phrase, secret format, or output risk.
---

# Add a detection rule

1. **Pick the pack.** Edit only the files under `sentinel/rules/`, never the stale top-level `rules/`:
   - `default.yaml` for user prompts (`check_input`)
   - `context.yaml` for retrieved docs and tool results (`check_context`)
   - `output.yaml` for model responses (`check_output`)
   Read the pack first and match its structure: `id`, `description`, `pattern`, plus the section
   or category used by its neighbours.

2. **Write the pattern.**
   - The pattern runs on *normalized*, case-insensitive text, so don't handle case or zero-width
     characters in the regex.
   - Use `\s+` between words and `\b` at the edges, and prefer bounded quantifiers (`{0,40}`)
     to `.*`.
   - Avoid nested quantifiers like `(a+)+` or `(\w+\s*)*` because they cause ReDoS.
   - Use a unique, snake_case `id`.

3. **Test it** in the relevant `tests/test_*.py` file (`test_pipeline.py` for input,
   `test_context_guard.py` for context, `test_output_handling.py` or `test_leakage.py` for output):
   - at least 2 positive cases, including one obfuscated variant (extra whitespace, mixed case,
     zero-width characters)
   - at least 2 benign near-misses that must stay `allow`
   - assert the rule `id` appears in the violations
   If the rule affects calibration, also add cases to `scripts/data/*.yaml`.

4. **Check it.**
   ```bash
   python -m pytest -q
   ```

5. **Document it.** If the rule extends OWASP coverage, update the relevant LLM0x section in
   `OWASP_MAPPING.md`, including its **Limits**.

6. Run the `security-reviewer` agent on the change.
