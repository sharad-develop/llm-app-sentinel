# llm-sentinel

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OWASP LLM Top 10 (2025)](https://img.shields.io/badge/OWASP%20LLM%20Top%2010-orange.svg)](OWASP_MAPPING.md)

Defense-in-depth security for LLM applications. `llm-sentinel` checks prompts, retrieved context, model responses, and agent tool calls before they cross a trust boundary.

It is an in-process Python SDK with no server or network hop.

## What it protects

- Direct and indirect prompt injection
- Secrets and PII in prompts and responses
- System-prompt leakage
- Unsafe HTML, links, images, and SQL-like output
- Excessive agent/tool permissions
- Unbounded request and token consumption
- Harmful model responses
- OWASP LLM Top 10 coverage — see the [OWASP coverage map](OWASP_MAPPING.md) for what is covered, partial, or out of scope

Every check returns one of:

| Verdict | Meaning |
|---|---|
| `allow` | Safe to continue, using the sanitized value when provided |
| `review` | Hold for an operator or application-specific review |
| `block` | Do not pass the value to the next stage |

Unavailable classifiers fail closed to `review` rather than silently allowing content.

For detailed OWASP coverage and limitations, see [OWASP_MAPPING.md](OWASP_MAPPING.md).

## Architecture

```text
your code ─▶ Guard (in-process)
  │
  │  every check applies the configured per-caller limits
  │
  ├─▶ guard.check_input(prompt)
  │       ├─ 1. Normalization    (NFC, zero-width strips, HTML decode, whitespace)
  │       ├─ 2. Rule checks      (injection phrases, fake delimiters, secrets, blobs)
  │       ├─ 3. Classifier       (Prompt Guard 2, local, chunked scoring)
  │       └─ 4. Policy           (capabilities, topics, PII per application)
  │                ▼ allow | review | block
  │
  ├─▶ guard.check_context(document, source=...)
  │   retrieved pages, emails, and tool results — before the model reads them
  │       ├─ hidden-content scan + normalization
  │       ├─ context rules + Prompt Guard 2
  │       └─ guard.wrap_untrusted(...) fences surviving content
  │
  ├─▶ [your LLM / agent call]
  │
  ├─▶ guard.check_output(response, prompt=..., system_prompt=..., canaries=[...])
  │       ├─ leakage checks       (rules, canaries, semantic similarity)
  │       ├─ output handling      (secrets, SQL, images, links, HTML)
  │       ├─ application policy   (topics and PII redaction)
  │       └─ safety classifier    (Llama Guard)
  │                ▼ allow | review | block
  │
  └─▶ guard.check_tool_call(tool, arguments, ...)
          deny-by-default allowlist → typed arguments → path/URL/SQL/shell checks
                   ▼ allow | review | block

Models are local, revision-pinnable, and loaded without remote code execution.
```

## Install

```bash
# Core package: rules, normalization, policies, and SDK
pip install -e .

# Local ML classifiers and PII detection
pip install -e ".[ml]"

# Development and security tooling
pip install -e ".[dev]"
pip install -e ".[security]"
```

Models download on first use and are cached locally. Prompt injection classification and output safety use **gated Meta models** (Llama Prompt Guard 2 and Llama Guard 3): request access on Hugging Face and log in before first use, or those checks return `review` for every request. See **[MODELS.md](MODELS.md)** for the full model list, access steps, pre-downloading, revision pinning, and what happens when a model is unavailable.

## Quick start

```python
from sentinel import Guard

guard = Guard.from_policy("policies")

incoming = guard.check_input(
    user_prompt,
    application_id="support-bot",
    user_id="u123",
    capabilities=["web_search"],
)
if incoming.verdict != "allow":
    raise RuntimeError(f"input requires review: {incoming.verdict}")

response = my_llm(incoming.sanitized_prompt)
outgoing = guard.check_output(
    response,
    prompt=user_prompt,
    application_id="support-bot",
)
if outgoing.verdict != "allow":
    raise RuntimeError(f"output requires review: {outgoing.verdict}")

print(outgoing.sanitized_output)
```

Models load lazily. Use `guard.load()` during application startup if you prefer eager loading.

## Examples

The [`examples/`](examples/) directory keeps workflows separate and runnable:

| Example | Demonstrates |
|---|---|
| [`basic_usage.py`](examples/basic_usage.py) | Input and output guard loop with policy and PII redaction |
| [`context_and_tools.py`](examples/context_and_tools.py) | Indirect-injection checks, untrusted-content fencing, and tool authorization |
| [`system_prompt_canary.py`](examples/system_prompt_canary.py) | Canary-based system-prompt leakage detection |

Each example uses the local SDK; none requires a REST service.

## Policies

Policies are YAML files in `policies/`, selected by `application_id`. See [`policies/support-bot.yaml`](policies/support-bot.yaml) for the complete example.

```yaml
id: support-bot

capabilities:
  allowed: [web_search, kb_lookup]
  blocked: [code_execution, file_write]

topics:
  blocked:
    - id: medical_advice
      keywords: [diagnosis, prescription, dosage]

pii:
  action: redact       # block | redact | flag
  entities: [EMAIL, PHONE, PERSON, ADDRESS]

tools:
  allowed:
    search_kb:
      args:
        query: {type: string, required: true, max_length: 500}
    read_doc:
      args:
        path: {kind: path, roots: [/srv/docs], required: true}
```

Use a custom `identity_provider` to resolve users and roles from your IAM. The bundled static provider is only a development placeholder.

## Main SDK methods

| Method | Use it for |
|---|---|
| `check_input()` | Validate a user prompt before the LLM call |
| `check_context()` | Inspect retrieved documents, web pages, emails, and tool results |
| `check_output()` | Validate and sanitize the model response |
| `check_tool_call()` | Authorize a tool call before executing it |
| `wrap_untrusted()` | Fence context that passed inspection before adding it to a prompt |
| `with_canary()` | Add a system-prompt canary for leakage detection |

Use `raise_on_block=True` or import `PromptBlocked`, `OutputBlocked`, `ContextBlocked`, and `ToolBlocked` when exceptions are preferable to inspecting response objects.

## Configuration essentials

All environment variables use the `SENTINEL_` prefix. Defaults and the complete configuration surface are defined in [`sentinel/config.py`](sentinel/config.py).

| Setting | Purpose |
|---|---|
| `SENTINEL_DISABLE_CLASSIFIER` | Disable Prompt Guard; checks then return `review` when classification is required |
| `SENTINEL_DISABLE_PII` | Disable PII detection; configured PII policies fail closed to `review` |
| `SENTINEL_DISABLE_SAFETY` | Disable Llama Guard; output safety becomes `review` |
| `SENTINEL_DISABLE_SEMANTIC_LEAK` | Disable the embedding-based system prompt paraphrase check; the canary leak check still runs |
| `SENTINEL_RATE_LIMIT_REQUESTS` | Per-caller request limit; `0` disables it |
| `SENTINEL_TOKEN_BUDGET_TOKENS` | Per-caller estimated-token budget; `0` disables it |
| `SENTINEL_MAX_PROMPT_LENGTH` / `SENTINEL_MAX_OUTPUT_LENGTH` | Text size limits |
| `SENTINEL_REQUIRE_PINNED_MODELS` | Require 40-character Hugging Face commit hashes |

For model supply-chain setup:

```bash
python scripts/pin_models.py
```

Review the revisions, commit them to deployment configuration, and enable `SENTINEL_REQUIRE_PINNED_MODELS=true`.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

Threshold calibration for real models is available through:

```bash
python scripts/calibrate.py leak
python scripts/calibrate.py context
```

The unit suite disables ML models through `tests/conftest.py` so it remains fast and deterministic.

## Project layout

```text
sentinel/            In-process Python SDK
policies/            Per-application policy examples
sentinel/rules/      Input, output, and context rule packs
tests/               Unit and SDK tests
examples/            Basic SDK, context/tool, and canary examples
scripts/             Model pinning and threshold calibration
OWASP_MAPPING.md     Detailed OWASP coverage and limitations
MODELS.md            ML model access, download, and pinning
```

## Important limitations

This library is a guard, not a sandbox or IAM system. Keep least privilege in the tool runtime, use parameterized queries, encode output at the final sink, enforce tenant access in the data layer, and apply global rate limits at your gateway. In-memory limits are per process. ML thresholds should be calibrated against representative traffic.

## License

MIT
