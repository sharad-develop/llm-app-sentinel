# prompt-citadel

**Defense-in-depth input and output guard for LLM applications.**

Prompt injection, jailbreaks, secret leakage, PII exposure, and harmful model responses are constant threats for any product built on an LLM. prompt-citadel sits between your client and your model — it analyzes every incoming prompt and outgoing response through layered pipelines of cheap deterministic checks followed by ML-based classification and configurable policy enforcement.

```
client
  │
  ├─▶ POST /v1/input/analyze
  │       │
  │       ├─ 1. Schema validation   (Pydantic — malformed requests rejected at 422)
  │       ├─ 2. Normalization       (NFC, zero-width strips, HTML decode, whitespace)
  │       ├─ 3. Rule checks         (injection phrases, fake delimiters, secrets, blobs)
  │       ├─ 4. Classifier          (Prompt Guard 2, 86M — local, chunked scoring)
  │       └─ 5. Policy              (capabilities, topics, PII per application)
  │                │
  │                ▼ verdict: allow | review | block
  │
  ├─▶ [forward prompt to your LLM]
  │
  └─▶ POST /v1/output/analyze
          │
          ├─ 1. Schema validation   (length, control chars, unknown fields → 422)
          ├─ 2. Normalization       (same canonicalization as input)
          ├─ 3. Rule checks         (system-prompt leakage, secrets in responses)
          ├─ 4. Policy              (topics, PII redaction per application)
          └─ 5. Safety classifier   (Llama Guard 3-1B — safe/unsafe + hazard categories)
                   │
                   ▼ verdict: allow | review | block
```

Each stage short-circuits on `block` — expensive ML stages only run when cheap deterministic ones pass. The design is **fail-safe throughout**: an unavailable classifier returns `review`, never `allow`.

---

## Goals

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

## Input pipeline

### Stage 1 — Schema validation

Pydantic v2 validates the request at the boundary. Unknown fields, wrong types, missing required fields, or a prompt exceeding `CITADEL_MAX_PROMPT_LENGTH` (default 8192) are all rejected with a structured `422` before any pipeline logic runs. Control characters (configurable via `CITADEL_CONTROL_CHARS_PATTERN`) are rejected here.

### Stage 2 — Normalization

Canonicalizes the text so later stages see a consistent representation regardless of encoding tricks:

- Unicode NFC normalization
- Strip invisible/zero-width/bidi-override characters (U+200B–U+202E, U+FEFF, etc.)
- Single-pass HTML entity decode (one round only, so `&amp;lt;` doesn't become `<`)
- Collapse excessive whitespace/newline runs
- Trim leading/trailing whitespace

The normalized text flows into every subsequent stage. `sanitized_prompt` in the response is always the normalized (and potentially PII-redacted) version, never the raw input.

### Stage 3 — Rule checks

A YAML rule pack (`rules/default.yaml`) defines regex pattern categories:

| Category | Examples |
|----------|----------|
| `injection_patterns` | role override phrases, "reveal system prompt", jailbreak markers |
| `delimiter_patterns` | fake `[SYSTEM]` / `<\|im_start\|>` tokens, chat template injections |
| `secret_patterns` | OpenAI/Anthropic keys, AWS access keys, GitHub tokens, PEM blocks |

A base64/hex ratio heuristic catches obfuscated payloads: if more than 40% of the prompt is base64-like blobs (≥ 40 chars each), it's flagged.

Any match produces a `block` with a `violations` list. Add patterns under any category — no code changes required.

### Stage 4 — Classifier

[Meta Llama Prompt Guard 2 (86M)](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) runs locally via `transformers`. The model's context window is 512 tokens; prompts longer than that are scored in overlapping 128-token-stride chunks so an attacker can't hide a payload past the truncation boundary.

The malicious label ID is resolved from `model.config.label2id` at startup — the classifier fails safe if the model has no recognizable label rather than silently scoring everything benign.

**Verdicts from score thresholds:**

| Score | Verdict |
|-------|---------|
| `< medium` (default 0.50) | `allow` |
| `medium ≤ score < high` (default 0.90) | `review` |
| `≥ high` | `block` |

Per-request threshold overrides are supported via `options.thresholds`.

### Stage 5 — Policy (per application)

The policy stage runs only when `context.application_id` is present. It evaluates three sub-checks in order — policy can only **downgrade** the verdict (`allow` → `review` → `block`), never upgrade it.

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

## Output pipeline

### Threat model

| Threat | Caught by |
|--------|-----------|
| Model discloses its system prompt / hidden instructions | Output rule pack (`leak_patterns`) |
| Credentials or API keys in a response | Output rule pack (`secret_patterns`) |
| Raw chat-template tokens leaking into output | Output rule pack (`leak_patterns`) |
| Harmful content (violence, CSAM, weapons, self-harm, …) | Llama Guard 3-1B (14 hazard categories) |
| Blocked topics appearing in responses | Per-application policy (topics) |
| PII exposure to end users | Per-application policy (PII detect → block/redact/flag) |

### Stage 3 — Output rule checks

`rules/output.yaml` defines two categories:

| Category | Patterns |
|----------|----------|
| `leak_patterns` | `system_prompt_disclosure`, `instruction_recital`, `chat_template_tokens` |
| `secret_patterns` | Same key formats as the input pack |

### Stage 4 — Policy (output)

The same per-application YAML drives both directions. For outputs, only **topics** and **PII** apply — capability checks are a request-time concern. PII redaction lands in `sanitized_output`.

Policy runs **before** the safety classifier so Llama Guard judges the sanitized text (what would actually be shown to the user). When a policy declares PII handling, S7 (privacy) is excluded from Llama Guard enforcement for that request — Llama Guard otherwise flags even redacted `[EMAIL_1]`-style placeholders.

### Stage 5 — Llama Guard 3 safety classifier

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

`CITADEL_SAFETY_EXCLUDED_CATEGORIES` (e.g. `S6,S13`) excludes specific categories from enforcement. Exclusion filters the verdict, not the prompt — if everything the model flagged is excluded the result is `safe` with a note; if anything else was also flagged the block stands.

---

## Identity and roles

prompt-citadel does **not** manage users. It resolves a `user_id` into roles via the `IdentityProvider` protocol — you supply an implementation backed by your IAM:

```python
# app/identity.py
@runtime_checkable
class IdentityProvider(Protocol):
    def resolve(self, user_id: str) -> Identity: ...
```

Register your implementation in `app/main.py`:

```python
from app.identity import Identity, IdentityProvider

class OktaIdentityProvider:
    def resolve(self, user_id: str) -> Identity:
        profile = my_okta_client.get_user(user_id)
        return Identity(user_id=user_id, roles=profile.roles)

# in lifespan:
app.state.identity_provider = OktaIdentityProvider()
```

The shipped `StaticIdentityProvider` reads an optional `identities.yaml` and falls back to `["default"]` for unknown users. It exists so the pipeline works out of the box — replace it for production.

---

## Install

```bash
# API only (no ML models — good for policy-only or CI use)
pip install -e ".[dev]"

# With local ML inference (all classifiers + PII detector)
pip install -e ".[ml,dev]"
```

**Gated models on Hugging Face:**

- `meta-llama/Llama-Prompt-Guard-2-86M` — request access and run `huggingface-cli login`, or set `CITADEL_CLASSIFIER_MODEL=gravitee-io/Llama-Prompt-Guard-2-86M-onnx` (ungated mirror)
- `meta-llama/Llama-Guard-3-1B` — request access similarly, or point `CITADEL_SAFETY_MODEL` at an ungated mirror

Models are downloaded on first run (~350 MB for Prompt Guard 2, ~2 GB for Llama Guard 3-1B) and served from local cache on every subsequent startup. The service works fully offline after the first pull.

---

## Run

```bash
uvicorn app.main:app --port 8000
```

Expected startup log (clean, five lines):

```
INFO:prompt_citadel.classifier:loaded classifier ... on mps (malicious label ids: [1])
INFO:prompt_citadel.safety:loaded safety classifier meta-llama/Llama-Guard-3-1B on mps
INFO:prompt_citadel.policy:loaded 1 policies from .../policies
INFO:prompt_citadel.pii:loaded PII model iiiorg/piiranha-v1-detect-personal-information
INFO:prompt_citadel.pii:loaded PII NER model dslim/bert-base-NER
INFO:prompt_citadel.identity:loaded 2 static identities from .../identities.yaml
```

---

## API reference

### `POST /v1/input/analyze`

**Request**

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

`context` and `options` are optional. Policy evaluation only runs when `application_id` is present.

**Response**

```json
{
  "request_id": "uuid",
  "verdict": "allow | review | block",
  "risk_score": 0.94,
  "blocked_at": "rule_checks | classifier | policy",
  "prompt_hash": "sha256:…",
  "sanitized_prompt": "…normalized, possibly PII-redacted…",
  "pipeline": {
    "schema_validation": { "passed": true },
    "normalization": { "applied": ["strip_invisible"] },
    "rule_checks": { "passed": false, "violations": ["role_override"] },
    "classifier": { "ran": true, "score": 0.98, "model": "…" },
    "policy": {
      "evaluated": true,
      "capability_violations": [],
      "topic_matches": [],
      "pii": { "found": ["EMAIL", "PERSON"], "action": "redact" }
    }
  },
  "meta": { "latency_ms": 42, "timestamp": "2024-01-01T00:00:00Z" }
}
```

- `blocked_at` and `risk_score` are omitted when not applicable.
- `sanitized_prompt` is omitted on `block`.

---

### `POST /v1/output/analyze`

Vets a **model response** before it reaches the end user.

**Request**

```json
{
  "output": "model response to vet (required, 1–16384 chars)",
  "prompt": "the user prompt it answered (optional, improves Llama Guard accuracy)",
  "context": {
    "application_id": "string | null",
    "user_id": "string | null",
    "session_id": "string | null"
  }
}
```

**Response**

```json
{
  "request_id": "uuid",
  "verdict": "allow | review | block",
  "blocked_at": "rule_checks | safety | policy",
  "safety_categories": ["non_violent_crimes"],
  "output_hash": "sha256:…",
  "sanitized_output": "…normalized, possibly PII-redacted…",
  "pipeline": {
    "schema_validation": { "passed": true },
    "normalization": { "applied": [] },
    "rule_checks": { "passed": true, "violations": [] },
    "policy": {
      "evaluated": true,
      "topic_matches": [],
      "pii": { "found": ["EMAIL", "PERSON"], "action": "redact" }
    },
    "safety": {
      "ran": true,
      "safe": true,
      "categories": [],
      "model": "meta-llama/Llama-Guard-3-1B",
      "note": "ignored_categories: privacy"
    }
  },
  "meta": { "latency_ms": 210, "timestamp": "2024-01-01T00:00:00Z" }
}
```

- `sanitized_output` is omitted on `block`.
- `safety_categories` lists the hazard category names that caused the block.
- When a policy handles PII, the safety `note` records suppressed categories (e.g. `ignored_categories: privacy`).

---

### `GET /healthz`

```json
{ "status": "ok", "classifier_loaded": true, "safety_loaded": true }
```

---

## Configure

All values can be set in `.env` (prefix `CITADEL_`) or as environment variables. Copy `.env.example` to get started.

### Input pipeline

| Variable | Default | Effect |
|----------|---------|--------|
| `CITADEL_MAX_PROMPT_LENGTH` | `8192` | Maximum prompt length in characters |
| `CITADEL_CONTROL_CHARS_PATTERN` | `\x00-\x08…` | Control chars that reject the request |
| `CITADEL_RULES_FILE` | `rules/default.yaml` | Input rule pack path |
| `CITADEL_CLASSIFIER_MODEL` | `meta-llama/Llama-Prompt-Guard-2-86M` | Classifier model id or local path |
| `CITADEL_CLASSIFIER_DEVICE` | `auto` | Device: `auto` (cuda→mps→cpu) or explicit |
| `CITADEL_DISABLE_CLASSIFIER` | `false` | Skip the classifier stage entirely |
| `CITADEL_CLASSIFIER_THRESHOLD_MEDIUM` | `0.50` | Score at which verdict becomes `review` |
| `CITADEL_CLASSIFIER_THRESHOLD_HIGH` | `0.90` | Score at which verdict becomes `block` |

### Policy

| Variable | Default | Effect |
|----------|---------|--------|
| `CITADEL_POLICIES_DIR` | `policies` | Directory of per-application policy YAML files |
| `CITADEL_PII_MODEL` | `iiiorg/piiranha-v1-detect-personal-information` | Structured PII model |
| `CITADEL_PII_NER_MODEL` | `dslim/bert-base-NER` | Secondary NER model for names/locations |
| `CITADEL_DISABLE_PII` | `false` | Skip PII detection entirely |
| `CITADEL_IDENTITIES_FILE` | `identities.yaml` | Static identity file (placeholder IAM) |

### Output pipeline

| Variable | Default | Effect |
|----------|---------|--------|
| `CITADEL_MAX_OUTPUT_LENGTH` | `16384` | Maximum output length in characters |
| `CITADEL_OUTPUT_RULES_FILE` | `rules/output.yaml` | Output rule pack path |
| `CITADEL_SAFETY_MODEL` | `meta-llama/Llama-Guard-3-1B` | Llama Guard model id or local path |
| `CITADEL_SAFETY_DEVICE` | `auto` | Device: `auto` (cuda→mps→cpu) or explicit |
| `CITADEL_DISABLE_SAFETY` | `false` | Skip the safety classifier entirely |
| `CITADEL_SAFETY_MAX_NEW_TOKENS` | `20` | Max tokens to generate for the verdict |
| `CITADEL_SAFETY_EXCLUDED_CATEGORIES` | `` | Comma-separated hazard codes to suppress, e.g. `S6,S13` |

---

## Test

```bash
# Unit + integration tests — runs in < 1s, no ML models loaded
pytest

# End-to-end against a running server
cd e2e && ./run_all.sh

# Individual scripts
bash e2e/01_clean_prompt.sh        # clean allow
bash e2e/11_classifier_block.sh    # classifier block
bash e2e/15_pii_redaction.sh       # input PII redaction
bash e2e/17_output_clean.sh        # clean output allow
bash e2e/18_output_secret_leak.sh  # secret in response
bash e2e/19_output_prompt_leak.sh  # system-prompt disclosure
bash e2e/20_output_unsafe_content.sh  # Llama Guard block
bash e2e/21_output_pii_redaction.sh   # output PII redaction
```

The test suite sets `CITADEL_DISABLE_CLASSIFIER=true`, `CITADEL_DISABLE_PII=true`, and `CITADEL_DISABLE_SAFETY=true` (in `tests/conftest.py`) so it never loads transformer models — CI stays fast.

---

## Project layout

```
prompt-citadel/
├── app/
│   ├── main.py              # FastAPI app, lifespan (loads all components)
│   ├── config.py            # All settings via pydantic-settings + .env
│   ├── audit.py             # JSON-line audit log to stdout (hash-only)
│   ├── identity.py          # IdentityProvider protocol + StaticIdentityProvider
│   ├── api/v1/
│   │   ├── input.py         # POST /v1/input/analyze — input pipeline
│   │   └── output.py        # POST /v1/output/analyze — output pipeline
│   ├── models/
│   │   ├── request.py       # AnalyzeRequest, OutputAnalyzeRequest, schemas
│   │   └── response.py      # AnalyzeResponse, OutputAnalyzeResponse, stage models
│   └── pipeline/
│       ├── normalization.py # Stage 2 — text canonicalization
│       ├── rules.py         # Stage 3 — YAML rule engine (input + output packs)
│       ├── classifier.py    # Input stage 4 — Prompt Guard 2 classifier
│       ├── safety.py        # Output stage 5 — Llama Guard 3 safety classifier
│       ├── pii.py           # PII detection + redact()
│       └── policy.py        # Stage 5/4 — capabilities / topics / PII policy
├── rules/
│   ├── default.yaml         # Input pack: injection, delimiter, secret patterns
│   └── output.yaml          # Output pack: leakage + secret patterns
├── policies/
│   └── support-bot.yaml     # Example application policy
├── tests/
│   ├── conftest.py          # Disables ML for fast test runs
│   ├── test_pipeline.py     # Normalization + rule engine unit tests
│   ├── test_api.py          # Input API integration tests
│   ├── test_output_api.py   # Output API integration tests
│   └── test_policy.py       # Policy engine + redact + identity tests
├── e2e/                     # curl scripts (00–21) for manual end-to-end testing
├── identities.example.yaml  # Template for static user→role mapping
├── .env.example             # Documents all CITADEL_ variables with defaults
└── pyproject.toml
```

---

## Audit log

Every request writes a JSON line to stdout:

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

Llama Guard generates output tokens (causal LM) rather than doing a single forward pass, which is why it's slower than Prompt Guard despite similar hardware. For high-throughput deployments, disable the safety classifier (`CITADEL_DISABLE_SAFETY=true`) or enforce it only on responses above a token-count threshold.

---

## Roadmap

- **Semantic topic classification** — replace keyword blocking with an embedding-based classifier (v2)
- **Async mode** — non-blocking classifiers for high-throughput deployments
- **OpenTelemetry** — structured spans per pipeline stage

---

## License

MIT
