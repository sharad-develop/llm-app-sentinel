# ML models: access, download, and pinning

Several llm-sentinel checks run local Hugging Face models. This page covers which models are
used, how to get access to the gated ones, how to download them ahead of time, and what happens
when a model is missing.

Install the ML extras first:

```bash
pip install -e ".[ml]"   # transformers + torch
```

## Models used

| Feature | Default model | Gated | Model setting | Disable flag |
|---|---|---|---|---|
| Prompt injection classifier (`check_input`, `check_context`) | [`meta-llama/Llama-Prompt-Guard-2-86M`](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) | **Yes** | `SENTINEL_CLASSIFIER_MODEL` | `SENTINEL_DISABLE_CLASSIFIER` |
| Output content safety (`check_output`) | [`meta-llama/Llama-Guard-3-1B`](https://huggingface.co/meta-llama/Llama-Guard-3-1B) | **Yes** | `SENTINEL_SAFETY_MODEL` | `SENTINEL_DISABLE_SAFETY` |
| PII detection | [`iiiorg/piiranha-v1-detect-personal-information`](https://huggingface.co/iiiorg/piiranha-v1-detect-personal-information) | No | `SENTINEL_PII_MODEL` | `SENTINEL_DISABLE_PII` |
| PII person names (secondary NER) | [`dslim/bert-base-NER`](https://huggingface.co/dslim/bert-base-NER) | No | `SENTINEL_PII_NER_MODEL` (empty = off) | `SENTINEL_DISABLE_PII` |
| System prompt paraphrase leak | [`sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2) | No | `SENTINEL_SEMANTIC_LEAK_MODEL` | `SENTINEL_DISABLE_SEMANTIC_LEAK` |

Models load lazily the first time a check needs them. The semantic leak model loads only when a
system prompt is supplied.

## 1. Request access to the gated models

The two Meta models are gated under the Llama community licence. You need a Hugging Face account
that has been granted access to each one.

1. Sign in at [huggingface.co](https://huggingface.co) (create an account if needed).
2. Open each model page:
   - [meta-llama/Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
   - [meta-llama/Llama-Guard-3-1B](https://huggingface.co/meta-llama/Llama-Guard-3-1B)
3. Fill in the access form and accept the licence. Each model is approved separately.
4. Check status at [huggingface.co/settings/gated-repos](https://huggingface.co/settings/gated-repos).
   Approval is usually quick but is not instant, so request it before you need it.

Access belongs to the account, so the token you use in step 2 must come from an approved account.

## 2. Authenticate

Create a **read** token at [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens).
A fine-grained token only needs read access to public gated repos.

Local development:

```bash
huggingface-cli login     # stores the token in ~/.cache/huggingface
```

CI, containers, and servers:

```bash
export HF_TOKEN=hf_...    # from your secret store; never commit it
```

## 3. Download ahead of time (recommended)

Downloading on first request makes that request slow and puts a network call on your hot path.
Fetch the models during build or deploy instead:

```bash
huggingface-cli download meta-llama/Llama-Prompt-Guard-2-86M
huggingface-cli download meta-llama/Llama-Guard-3-1B
huggingface-cli download iiiorg/piiranha-v1-detect-personal-information
huggingface-cli download dslim/bert-base-NER
huggingface-cli download sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2
```

Models are cached under `$HF_HOME/hub` (default `~/.cache/huggingface/hub`), or `$HF_HUB_CACHE`
if set. llm-sentinel always tries the local cache first and only contacts the Hub if the model
is not cached.

For air-gapped or locked-down runtimes, bake the cache into the image and set:

```bash
export HF_HUB_OFFLINE=1
```

Once the models are cached, the runtime does not need a token at all.

## 4. Pin revisions

Model repos can change under you. Pin each model to a reviewed commit:

```bash
python scripts/pin_models.py            # prints SENTINEL_*_REVISION exports for cached models
```

Commit the output to your deployment config and set `SENTINEL_REQUIRE_PINNED_MODELS=true`. With
that flag on, any model without a 40-character commit hash refuses to load (and its checks
return `review`, see below). Models are always loaded with `trust_remote_code=False`.

## 5. Hardware

All models run on CPU. Each stage picks a device automatically (CUDA, then Apple MPS, then CPU);
override with `SENTINEL_CLASSIFIER_DEVICE`, `SENTINEL_SAFETY_DEVICE`, or
`SENTINEL_SEMANTIC_LEAK_DEVICE` (`cuda`, `mps`, or `cpu`).

Llama Guard 3 1B is by far the largest model and the slowest on CPU. If output latency matters
and you have no GPU, consider running it only where you need content-safety categories.

## What happens when a model is missing

A model that cannot be loaded (no access, no token, offline without a cache, unpinned while
pinning is required) never causes an `allow`. The stage reports itself as not run and the check
falls back to `review`:

| Model missing | Effect |
|---|---|
| Prompt Guard 2 | `check_input` / `check_context` return `review` whenever classification is needed. Rule-based blocks still apply. |
| Llama Guard 3 | Output safety returns `review`. |
| piiranha | Policies that act on PII fail closed to `review`. |
| bert-base-NER | PII detection still runs, with weaker person-name coverage. |
| Semantic leak model | Verbatim/canary leak checks still run; the paraphrase check returns `review`. |

> **Watch for this:** if every request comes back `review`, check the logs for
> `classifier unavailable` or `safety classifier unavailable`. The most common cause is a missing
> Hugging Face token or a gated-model request that has not been approved yet.

## Using a different model

Point the setting at another model, for example an ungated mirror or a fine-tune:

```bash
export SENTINEL_CLASSIFIER_MODEL=your-org/your-prompt-guard-mirror
```

The replacement must have the same task and output format as the default (sequence
classification with malicious/benign labels for the classifier, Llama Guard's safe/unsafe output
and chat template for safety). Re-run `scripts/calibrate.py` after swapping the classifier.
Only use mirrors you trust, and pin them the same way.

To turn a stage off entirely, set its `SENTINEL_DISABLE_*` flag. Disabling the classifier, safety,
or PII stage makes the checks that need it return `review`. Disabling the semantic leak check
simply skips it; the canary leak check still runs.
