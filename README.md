# prompt-citadel

**Defense-in-depth input guard for LLM applications.**

Prompt injection, jailbreaks, secret leakage, and PII exposure are constant threats for any product built on an LLM. prompt-citadel sits between your client and your model — it analyzes every incoming prompt through a layered pipeline of cheap deterministic checks followed by ML-based classification and configurable policy enforcement. Anything suspicious is blocked or flagged before it ever reaches the model.

```
client
  └─▶ POST /v1/input/analyze
        │
        ├─ 1. Schema validation     (Pydantic — malformed requests rejected at 422)
        ├─ 2. Normalization         (Unicode NFC, zero-width strips, HTML decode, whitespace collapse)
        ├─ 3. Rule checks           (regex rule pack: injection phrases, fake delimiters, secrets, blobs)
        ├─ 4. Classifier            (Llama Prompt Guard 2, 86M — local inference, chunked scoring)
        └─ 5. Policy                (capabilities, topic blocks, PII detection/redaction per application)
              │
              ▼
           verdict: allow | review | block
```

Each stage can short-circuit with a `block`, so the expensive ML stages only run when the cheap deterministic ones pass. The design is **fail-safe throughout**: if the classifier is unavailable the pipeline returns `review`, never `allow`.

---

## Goals

| Goal | How it's achieved |
|------|-------------------|
| Stop prompt injection before it reaches the model | Rule engine + Prompt Guard 2 classifier |
| Catch jailbreaks that evade simple pattern matching | ML classifier with overlapping-chunk scoring for long prompts |
| Prevent secret leakage (API keys, credentials) | Regex rule pack covering major key formats |
| Redact PII before the prompt is forwarded | Dual-model PII detector (piiranha + bert-base-NER) |
| Let applications define their own capability and topic policies | Per-application YAML policy files |
| Never log sensitive prompt content | SHA-256 hash-only audit log to stdout |
| Work offline after first model pull | `local_files_only=True` on all model loads |
| Fast unit tests (< 1s) | Classifier and PII disable flags; no ML loaded in CI |

---

## Pipeline stages

### 1 — Schema validation

Pydantic v2 validates the request at the boundary. Unknown fields, wrong types, missing required fields, or a prompt exceeding `CITADEL_MAX_PROMPT_LENGTH` (default 8192) are all rejected with a structured `422` before any pipeline logic runs. Control characters (configurable via `CITADEL_CONTROL_CHARS_PATTERN`) are also rejected here.

### 2 — Normalization

Canonicalizes the text so later stages see a consistent representation regardless of encoding tricks:

- Unicode NFC normalization
- Strip invisible/zero-width/bidi-override characters (U+200B–U+202E, U+FEFF, etc.)
- Single-pass HTML entity decode (only one round, so `&amp;lt;` doesn't become `<`)
- Collapse excessive whitespace/newline runs
- Trim leading/trailing whitespace

The normalized text is what flows into every subsequent stage. `sanitized_prompt` in the response is always the normalized (and potentially PII-redacted) version, not the raw input.

### 3 — Rule checks

A YAML rule pack (`rules/default.yaml`) defines three categories of regex patterns:

| Category | Examples |
|----------|----------|
| `injection_patterns` | role override phrases, "reveal system prompt", jailbreak markers |
| `delimiter_patterns` | fake `[SYSTEM]` / `<|im_start|>` tokens, chat template injections |
| `secret_patterns` | OpenAI/Anthropic keys, AWS access keys, GitHub tokens, PEM blocks |

A base64/hex ratio heuristic catches obfuscated payloads: if more than 40% of the prompt is base64-like blobs (≥ 40 chars each), it's flagged.

Any match produces a `block` with a `violations` list naming which rules fired. Add your own patterns under any category — no code changes required.

### 4 — Classifier

[Meta Llama Prompt Guard 2 (86M)](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) runs locally via `transformers`. The model's context window is 512 tokens; prompts longer than that are scored in overlapping 128-token-stride chunks so an attacker can't hide a payload past the truncation boundary.

The malicious label ID is resolved from `model.config.label2id` at startup — the classifier fails safe (marking itself unavailable) if the model has no recognizable label, rather than silently scoring everything benign.

**Verdicts from score thresholds:**

| Score | Verdict |
|-------|---------|
| `< medium` (default 0.50) | `allow` |
| `medium ≤ score < high` (default 0.90) | `review` |
| `≥ high` | `block` |

Per-request threshold overrides are supported via `options.thresholds`.

### 5 — Policy (per application)

The policy stage runs only when `context.application_id` is present. It evaluates three sub-checks in order — a policy can only **downgrade** the verdict (`allow` → `review` → `block`), never upgrade it.

#### Capabilities

Applications declare which capabilities are allowed or blocked. Users requesting a capability not in the allowed list are blocked. Per-role overrides let privileged users (e.g. `admin`) access capabilities blocked for regular users.

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

#### Topic blocking

Keyword lists gate topics at the application level. Matches produce a `block` with the topic id in `pipeline.policy.topic_matches`.

```yaml
topics:
  blocked:
    - id: medical_advice
      keywords: [diagnosis, prescription, dosage]
```

#### PII detection and redaction

Two models run in tandem:

| Model | Strength |
|-------|----------|
| [`iiiorg/piiranha-v1-detect-personal-information`](https://huggingface.co/iiiorg/piiranha-v1-detect-personal-information) | Structured PII: emails, phones, SSNs, credit cards, addresses, IDs |
| [`dslim/bert-base-NER`](https://huggingface.co/dslim/bert-base-NER) | Person names and locations in prose (PER + LOC groups only) |

Spans from both models are merged, de-overlapped, and snapped to word boundaries via `_refine_span()`. The policy action (`block`, `redact`, or `flag`) is configured per application:

```yaml
pii:
  action: redact
  entities: [EMAIL, PHONE, SSN, CREDIT_CARD, PERSON, ADDRESS]
```

`redact` replaces entities with stable placeholders (`[EMAIL_1]`, `[PERSON_1]`, …) — the same value maps to the same placeholder within one prompt, so the LLM can still refer to redacted values coherently. The redacted prompt is returned in `sanitized_prompt`.

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

# With local ML inference (classifier + PII detector)
pip install -e ".[ml,dev]"
```

The default classifier model (`meta-llama/Llama-Prompt-Guard-2-86M`) is gated on Hugging Face. Either request access and run `huggingface-cli login`, or point `CITADEL_CLASSIFIER_MODEL` at an ungated mirror such as `gravitee-io/Llama-Prompt-Guard-2-86M-onnx`.

Models are downloaded on first run and served from the local cache on every subsequent startup (`local_files_only=True`). The service works fully offline after the first pull.

---

## Run

```bash
uvicorn app.main:app --port 8000
```

Startup log (clean, no noise):

```
INFO:prompt_citadel.classifier:loaded classifier ... on mps (malicious label ids: [1])
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
  "sanitized_prompt": "…redacted text…",
  "pipeline": {
    "schema_validation": { "passed": true },
    "normalization": { "applied": ["strip_invisible", "collapse_spaces"] },
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

### `GET /healthz`

Returns `{ "status": "ok", "classifier_loaded": true }`.

---

## Configure

All values can be set in `.env` (prefix `CITADEL_`) or as environment variables. Copy `.env.example` to get started.

| Variable | Default | Effect |
|----------|---------|--------|
| `CITADEL_MAX_PROMPT_LENGTH` | `8192` | Maximum prompt length in characters |
| `CITADEL_CLASSIFIER_MODEL` | `meta-llama/Llama-Prompt-Guard-2-86M` | Classifier model id or local path |
| `CITADEL_DISABLE_CLASSIFIER` | `false` | Skip the classifier stage entirely |
| `CITADEL_CLASSIFIER_THRESHOLD_MEDIUM` | `0.50` | Score at which verdict becomes `review` |
| `CITADEL_CLASSIFIER_THRESHOLD_HIGH` | `0.90` | Score at which verdict becomes `block` |
| `CITADEL_RULES_FILE` | `rules/default.yaml` | Path to the rule pack YAML |
| `CITADEL_POLICIES_DIR` | `policies` | Directory of per-application policy files |
| `CITADEL_PII_MODEL` | `iiiorg/piiranha-v1-detect-personal-information` | Structured PII model |
| `CITADEL_PII_NER_MODEL` | `dslim/bert-base-NER` | Secondary NER model for names/locations |
| `CITADEL_DISABLE_PII` | `false` | Skip PII detection entirely |
| `CITADEL_IDENTITIES_FILE` | `identities.yaml` | Static identity file (placeholder IAM) |

---

## Test

```bash
# Unit + integration tests — runs in < 1s, no ML models loaded
pytest

# End-to-end against a running server
cd e2e && ./run_all.sh
# or individual scripts:
bash e2e/01_clean_prompt.sh
bash e2e/15_pii_redaction.sh
```

The test suite uses `CITADEL_DISABLE_CLASSIFIER=true` and `CITADEL_DISABLE_PII=true` (set in `tests/conftest.py`) so it never loads the transformer models — CI stays fast.

---

## Project layout

```
prompt-citadel/
├── app/
│   ├── main.py              # FastAPI app, lifespan (loads all components)
│   ├── config.py            # All settings via pydantic-settings + .env
│   ├── audit.py             # JSON-line audit log to stdout (hash-only, no content)
│   ├── identity.py          # IdentityProvider protocol + StaticIdentityProvider
│   ├── api/v1/
│   │   └── input.py         # POST /v1/input/analyze — pipeline orchestration
│   ├── models/
│   │   ├── request.py       # AnalyzeRequest, PromptContext, AnalyzeOptions
│   │   └── response.py      # AnalyzeResponse and all stage result models
│   └── pipeline/
│       ├── normalization.py # Stage 2 — text canonicalization
│       ├── rules.py         # Stage 3 — YAML rule engine
│       ├── classifier.py    # Stage 4 — Prompt Guard 2 classifier
│       ├── pii.py           # PII detection + redact()
│       └── policy.py        # Stage 5 — capabilities / topics / PII policy
├── rules/
│   └── default.yaml         # Injection, delimiter, and secret patterns
├── policies/
│   └── support-bot.yaml     # Example application policy
├── tests/
│   ├── conftest.py          # Disables ML for fast test runs
│   ├── test_pipeline.py     # Normalization + rule engine unit tests
│   ├── test_api.py          # Integration tests (FakeClassifier, FakePII)
│   └── test_policy.py       # Policy engine + redact + identity tests
├── e2e/                     # curl scripts for manual end-to-end testing
├── identities.example.yaml  # Template for static user→role mapping
├── .env.example             # Documents all CITADEL_ variables
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

Prompt content is **never logged** — only the SHA-256 hash. Pipe stdout to your log aggregator to retain audit trails without storing sensitive user input.

---

## Roadmap

- **Output guard** (`POST /v1/output/analyze`) — schema validation, secret/PII detection, prompt-leakage checks on model responses
- **Semantic topic classification** — replace keyword topic blocking with an embedding-based classifier (v2)
- **Async mode** — non-blocking classifier for high-throughput deployments
- **OpenTelemetry** — structured spans per pipeline stage

---

## License

MIT
