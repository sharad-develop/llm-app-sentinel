# OWASP Top 10 for LLM Applications (2025) — coverage map

What llm-sentinel does for each risk, how to turn it on, and where it stops. "Covered" means a
mechanism exists and is tested; it does not mean the risk is eliminated — see **Limits** in each row.
llm-sentinel is a guard around your model calls, not a replacement for least privilege, output
encoding, or access control in the rest of your system.

| # | Risk | Status | Main mechanism |
|---|------|--------|----------------|
| LLM01 | Prompt injection | **Covered** (direct + indirect) | Rules, Prompt Guard 2, `check_context` |
| LLM02 | Sensitive information disclosure | **Covered** | PII redaction, secret rules, entropy scan |
| LLM03 | Supply chain | **Partial** | Revision pinning, `pip-audit`/`bandit`/`semgrep` in CI |
| LLM04 | Data and model poisoning | **Out of scope** (runtime partial) | `check_context` at ingestion time |
| LLM05 | Improper output handling | **Covered** | Output handling stage, SQL indicators |
| LLM06 | Excessive agency | **Covered** | Capabilities, `check_tool_call` |
| LLM07 | System prompt leakage | **Covered** | Canaries, semantic similarity |
| LLM08 | Vector and embedding weaknesses | **Partial** | `check_context` on retrieved chunks |
| LLM09 | Misinformation | **Out of scope** | — |
| LLM10 | Unbounded consumption | **Covered** | Length caps, rate limit, token budget |

---

## LLM01 — Prompt injection

**Direct** (user prompt): `check_input` runs normalization (invisible characters, HTML entities,
NFC), the injection/delimiter rule pack (including "ignore previous instructions" in nine languages besides English),
an encoded-blob check, then the Prompt Guard 2 classifier. Rule hit → `block`; score ≥ `high` →
`block`; ≥ `medium` → `review`; classifier unavailable → `review`.

**Indirect** (retrieved documents, web pages, emails, tool results): `Guard.check_context`
(gateway: `POST /v1/context/check`) scans untrusted content before the model reads it — invisible Unicode tag
characters are decoded and scanned, long invisible runs and CSS-hidden text are flagged, the
`context.yaml` pack catches text addressed to the AI / "new instructions:" / "don't tell the user" /
exfiltration directives / tool-call commands, and the classifier scores the whole document.
`Guard.wrap_untrusted` fences the content with unforgeable tags.

**Limits:** the classifier thresholds are untested on real traffic until you run
`scripts/calibrate.py context` on your data. Non-English coverage is the "ignore previous
instructions" family only; other phrasings rely on the classifier. No multi-turn tracking: each
call is judged alone, so an attack split across turns is not correlated.

## LLM02 — Sensitive information disclosure

- **PII:** per-application `pii:` policy (`block` / `redact` / `flag`) on input and output, using
  two local models (piiranha + bert-base-NER).
- **Secrets, known formats:** ~17 key/token formats (OpenAI, Anthropic, AWS, GitHub, GitLab, Slack,
  Stripe, Google, Hugging Face, npm, SendGrid, JWTs, PEM private keys, credentials in URLs) are
  **blocked** on input and output.
- **Secrets, unknown formats:** an entropy scan (`secrets:` in the policy `output:` section, or
  `SENTINEL_OUTPUT_SECRETS`: `allow | flag | redact | block`, default `flag`).
- **Tool arguments** are scanned too, since a tool call is an exfiltration path.

**Limits:** PII detection is a model, so it has misses and false alarms. Obfuscated or split
secrets (base64-wrapped, spaced out) are not caught. The guard sees only text you pass it — it cannot
stop a model from memorizing training data or enforce who may see which records (do that in your
data layer).

## LLM03 — Supply chain

- Pin each Hugging Face model to a commit hash (`SENTINEL_*_REVISION`); `scripts/pin_models.py`
  prints the revisions in your cache. `SENTINEL_REQUIRE_PINNED_MODELS=true` refuses to load
  anything unpinned or pinned to a mutable branch/tag — the stage then returns `review`.
- `trust_remote_code` is never used (enforced by a test).
- CI runs `pip-audit` (also weekly), `bandit` and `semgrep`.

**Limits:** pinning proves *which* weights load, not that they are benign — review a model before
pinning it. There is no SBOM, signature verification, or weight scanning. `pip-audit` covers the ML
extras only if they are installed in the CI environment.

## LLM04 — Data and model poisoning

Training-time risk; llm-sentinel is a runtime guard and does not see your training or fine-tuning
pipeline. What helps in practice: call `check_context` on documents **at ingestion** (not only at
query time) so poisoned text is quarantined before it enters your corpus, and pin the guard's own
models (LLM03).

## LLM05 — Improper output handling

The output handling stage (on by default) neutralizes what a response can do to the next consumer:
markdown images (a silent exfiltration channel) and links per policy (`allow | allowlist | strip |
block`), raw HTML via `nh3`, and `javascript:` / `data:` / `vbscript:` URLs. It parses with a real
CommonMark parser, rewrites, then re-parses to verify and **blocks if anything survives** (fail
closed). Opt-in SQL indicators (`sql: flag | block | readonly`) catch stacked/destructive statements,
tautologies, `UNION SELECT`, comment truncation, time delays and file/exec primitives.

**Limits:** this reduces risk; it does not replace encoding at the sink (escape HTML, parameterized
queries, no `shell=True`). SQL detection is heuristic and matches statements at line / fence /
inline-code starts. Shell injection in free-form *output text* is not detected (only in tool
arguments, via `kind: shell`). Coding assistants should set `html: allow`.

## LLM06 — Excessive agency

- **Capabilities** (`capabilities:` + per-role overrides) gate what the model may be granted per
  request.
- **`check_tool_call`** (gateway: `POST /v1/tools/check`) is deny-by-default against the policy's `tools:`
  section: unlisted tools, undeclared/missing/mistyped arguments, path traversal outside `roots`,
  SSRF-prone URLs, non-read-only SQL, shell metacharacters and secrets in arguments are blocked.
  `confirm: true` returns `review` so a human approves the action.
- Tool *results* go back through `check_context` (LLM01).

**Limits:** it validates what the model asked for; it cannot see symlinks, DNS rebinding, or what
the tool does internally. There are no per-session call caps and no sequence rules (read-then-email).
Keep least privilege at the tool itself.

## LLM07 — System prompt leakage

- **Canary tokens:** `Guard.with_canary(prompt)` plants a random marker; any appearance in a
  response → `block`.
- **Semantic similarity** (optional, `SENTINEL_DISABLE_SEMANTIC_LEAK` / per-call `semantic_leak`):
  response sentences are compared with the real system prompt by embedding; a close restatement →
  `block`. If it is wanted but cannot run, the verdict is `review`.
- Output rules catch phrases like "my system prompt is…" and raw chat-template tokens.

**Limits:** the 0.80 threshold is a starting value — run `scripts/calibrate.py leak` on your own
prompts. A prompt leaked in re-encoded form (base64, ROT13, another language through a different
model) is not caught. The real mitigation is to keep secrets and access rules out of the prompt.

## LLM08 — Vector and embedding weaknesses

**Partial.** `check_context` vets retrieved chunks (and, at ingestion, documents) for injected
instructions and hidden content, which is the attack that vector stores make easy to plant. Not
covered: per-tenant access control and filtering in the vector store, embedding-inversion
attacks, and the security of the vector database itself — these belong in your retrieval layer.

## LLM09 — Misinformation

**Not covered.** A guard cannot verify facts. The Llama Guard safety categories target harmful
content, not factual accuracy. A grounding check (comparing an answer with its retrieved sources)
would be the natural addition; it is not implemented. Mitigate with retrieval, citations, human
review for high-stakes answers, and the `review` verdict as a hold point.

## LLM10 — Unbounded consumption

| Control | Setting |
|---------|---------|
| Max prompt / output / context length | `SENTINEL_MAX_PROMPT_LENGTH`, `SENTINEL_MAX_OUTPUT_LENGTH`, `SENTINEL_MAX_CONTEXT_LENGTH` |
| Max request body (REST) | `SENTINEL_MAX_REQUEST_BYTES` — gateway setting (411/413) |
| Bounded classifier work | `SENTINEL_CLASSIFIER_MAX_CHUNKS`, `SENTINEL_CONTEXT_CLASSIFIER_MAX_CHUNKS` — too long to score → `review`, never silently truncated |
| Request rate limit per caller | `SENTINEL_RATE_LIMIT_REQUESTS` / `_WINDOW_SECONDS` (off by default) |
| Token budget per caller | `SENTINEL_TOKEN_BUDGET_TOKENS` / `_WINDOW_SECONDS` (off by default) |
| Tool-call size caps | `SENTINEL_TOOL_MAX_ARGS_BYTES`, `SENTINEL_TOOL_ARG_MAX_LENGTH` |
| Memory bound on counters | `SENTINEL_RATE_LIMIT_MAX_KEYS` (fails closed when full) |

**Limits:** counters are per process, so the real limit is `limit × replicas` — enforce strict global
limits at your gateway. Token counts are an estimate (~4 chars/token ASCII, 1 per non-ASCII
character), not your model's tokenizer, and only text passed through the guard is counted — it does
not see your provider's actual billing.

---

## Verifying

```bash
pytest                          # SDK tests, no ML models needed (REST tests + e2e are in llm-sentry-gateway)
python scripts/calibrate.py leak     # real-model checks (needs `pip install -e ".[ml]"`)
python scripts/calibrate.py context
```
