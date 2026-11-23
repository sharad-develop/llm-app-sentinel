"""Application configuration.

Values are read in this order (highest wins):
  1. Environment variables prefixed with SENTINEL_
  2. .env file in the project root
  3. Defaults defined here

Typical .env file:

    SENTINEL_MAX_PROMPT_LENGTH=4096
    SENTINEL_CONTROL_CHARS_PATTERN=[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]
    SENTINEL_CLASSIFIER_MODEL=meta-llama/Llama-Prompt-Guard-2-86M
    SENTINEL_DISABLE_CLASSIFIER=false
    SENTINEL_CLASSIFIER_THRESHOLD_MEDIUM=0.50
    SENTINEL_CLASSIFIER_THRESHOLD_HIGH=0.90
"""
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- request validation ---
    max_prompt_length: int = 8192
    # Raw regex character class body (without surrounding brackets).
    # Default blocks control chars below 0x20 except \n (0x0a) and \t (0x09),
    # plus DEL (0x7f).
    control_chars_pattern: str = r"\x00-\x08\x0b\x0c\x0e-\x1f\x7f"

    # --- resource limits (OWASP LLM10: unbounded consumption) ---
    # Reject REST bodies larger than this before parsing (bytes).
    max_request_bytes: int = 1_048_576
    # Per-caller request budget: at most `rate_limit_requests` calls per
    # `rate_limit_window_seconds`, keyed by user_id, else application_id, else
    # client address. 0 disables rate limiting.
    rate_limit_requests: int = 0
    rate_limit_window_seconds: float = 60.0
    # Cap on distinct rate-limit keys tracked in memory.
    rate_limit_max_keys: int = 10_000

    # --- normalization ---
    # Full regex pattern for invisible / zero-width characters to strip.
    # Covers U+200B-U+200F (zero-width/LRM/RLM), U+2028-U+2029 (line/para
    # separators), U+202A-U+202E (bidi overrides), U+2060-U+2064 (word
    # joiner / invisible operators), U+FEFF (BOM).
    invisible_chars_pattern: str = (
        "\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\ufeff"
    )
    # Minimum consecutive spaces/tabs before collapsing to one space.
    max_space_run: int = 2
    # Minimum consecutive newlines before collapsing to two newlines.
    max_newline_run: int = 3

    # --- rule checks ---
    # Filename of the YAML rule pack inside the app/rules/ package directory.
    rules_file: str = "default.yaml"
    # Regex for base64-like blobs (full pattern, not a character class body).
    base64_blob_pattern: str = r"[A-Za-z0-9+/=]{40,}"
    # Regex for hex-encoded blobs.
    hex_blob_pattern: str = r"(?:[0-9a-fA-F]{2}){20,}"
    # Fraction of prompt that may be base64/hex before flagging.
    max_encoded_ratio: float = 0.4
    # Minimum blob length (chars) before it counts toward the ratio.
    min_blob_length: int = 40

    # --- classifier ---
    classifier_model: str = "meta-llama/Llama-Prompt-Guard-2-86M"
    disable_classifier: bool = False
    classifier_threshold_medium: float = 0.50
    classifier_threshold_high: float = 0.90
    # Device for classifier: auto (cuda→mps→cpu), or explicit (cuda/mps/cpu).
    classifier_device: str = "auto"
    # Max 512-token chunks scored per prompt. Longer prompts are not scored
    # (fail-safe: verdict `review`) rather than silently truncated.
    classifier_max_chunks: int = 8

    # --- system-prompt leakage (OWASP LLM07) ---
    # Optional semantic (embedding) comparison: catches paraphrase/translation.
    # Runs only when a system prompt is supplied; model loads lazily.
    disable_semantic_leak: bool = False
    semantic_leak_model: str = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
    semantic_leak_device: str = "auto"
    # Cosine similarity at which a response sentence counts as restating a
    # system-prompt sentence.
    semantic_leak_threshold: float = 0.80
    # Sentences shorter than this (in words) are ignored on both sides.
    semantic_leak_min_words: int = 4
    # Max segments per side; beyond it the stage skips (verdict `review`).
    semantic_leak_max_segments: int = 256
    max_system_prompt_length: int = 32768
    max_canaries: int = 16

    # --- output handling (OWASP LLM05) ---
    # Defaults for responses; a policy file's `output:` section overrides them
    # per application. images/links: allow | allowlist | strip | block.
    # html: allow | sanitize | block.
    disable_output_handling: bool = False
    output_images: str = "strip"
    output_links: str = "allow"
    output_html: str = "sanitize"
    # SQL-injection indicators in responses: allow | flag (verdict `review`) |
    # block | readonly (block + refuse any INSERT/UPDATE/DELETE/DDL). Off by
    # default because ordinary answers contain SQL; enable for text-to-SQL.
    output_sql: str = "allow"
    # Secrets of no known format (key=value assignments, high-entropy tokens):
    # allow | flag (verdict `review`) | redact | block. Known key formats are
    # always blocked by the output rule pack.
    output_secrets: str = "flag"
    # Comma-separated hosts (and their subdomains) for the `allowlist` mode.
    output_allowed_domains: str = ""

    # --- tool-call guard (LLM06) ---
    # Max serialized size of one tool call's arguments, and the default
    # max length of a string argument (a policy can override per argument).
    tool_max_args_bytes: int = 16384
    tool_arg_max_length: int = 4096

    # --- output guard ---
    # Maximum model-output length in characters.
    max_output_length: int = 16384
    # Filename of the output rule pack inside the app/rules/ package directory.
    output_rules_file: str = "output.yaml"
    # Llama Guard content-safety model. Generates safe/unsafe verdicts with
    # hazard categories (S1..S14). Gated on Hugging Face — request access
    # or point at an ungated mirror.
    safety_model: str = "meta-llama/Llama-Guard-3-1B"
    disable_safety: bool = False
    # Verdict + category codes fit comfortably in a few tokens.
    safety_max_new_tokens: int = 20
    # Device for safety classifier: auto (cuda→mps→cpu), or explicit (cuda/mps/cpu).
    safety_device: str = "auto"
    # Comma-separated Llama Guard hazard codes to exclude from enforcement,
    # e.g. "S6,S13" to allow specialized advice and elections content.
    safety_excluded_categories: str = ""

    # --- REST API authentication ---
    # When set, every request to the REST API must include the header:
    #   Authorization: Bearer <value>
    # Leave unset (empty) only in trusted network environments where the API
    # is not reachable from untrusted callers (mTLS, VPC policy, service mesh).
    api_key: str = ""

    # --- policy ---
    # Directory of per-application policy YAML files (<application_id>.yaml).
    policies_dir: str = "policies"
    # PII token-classification model for the redact/block/flag actions.
    pii_model: str = "iiiorg/piiranha-v1-detect-personal-information"
    # Secondary NER model: piiranha is strong on structured PII (emails,
    # phones, ids) but misses person names in prose; this fills that gap.
    # Set empty to disable the second model.
    pii_ner_model: str = "dslim/bert-base-NER"
    disable_pii: bool = False
    # Optional static identity file for the placeholder IdentityProvider.
    identities_file: str = "identities.yaml"

    @field_validator("max_prompt_length")
    @classmethod
    def positive_length(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_prompt_length must be >= 1")
        return v

    @field_validator("max_request_bytes", "classifier_max_chunks", "rate_limit_max_keys")
    @classmethod
    def positive_int(cls, v: int) -> int:
        if v < 1:
            raise ValueError("value must be >= 1")
        return v

    @field_validator("rate_limit_requests")
    @classmethod
    def non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("rate_limit_requests must be >= 0")
        return v

    @field_validator("rate_limit_window_seconds")
    @classmethod
    def positive_window(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("rate_limit_window_seconds must be > 0")
        return v

    @field_validator("max_system_prompt_length", "max_canaries")
    @classmethod
    def leak_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("value must be >= 1")
        return v

    @field_validator("output_images", "output_links")
    @classmethod
    def valid_link_mode(cls, v: str) -> str:
        if v not in {"allow", "allowlist", "strip", "block"}:
            raise ValueError("must be one of allow, allowlist, strip, block")
        return v

    @field_validator("output_secrets")
    @classmethod
    def valid_secrets_mode(cls, v: str) -> str:
        if v not in {"allow", "flag", "redact", "block"}:
            raise ValueError("must be one of allow, flag, redact, block")
        return v

    @field_validator("output_sql")
    @classmethod
    def valid_sql_mode(cls, v: str) -> str:
        if v not in {"allow", "flag", "block", "readonly"}:
            raise ValueError("must be one of allow, flag, block, readonly")
        return v

    @field_validator("output_html")
    @classmethod
    def valid_html_mode(cls, v: str) -> str:
        if v not in {"allow", "sanitize", "block"}:
            raise ValueError("must be one of allow, sanitize, block")
        return v

    @field_validator("semantic_leak_threshold")
    @classmethod
    def semantic_fraction(cls, v: float) -> float:
        if not 0.0 < v <= 1.0:
            raise ValueError("semantic_leak_threshold must be in (0, 1]")
        return v

    @field_validator("semantic_leak_min_words", "semantic_leak_max_segments")
    @classmethod
    def semantic_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("value must be >= 1")
        return v

    @field_validator("classifier_threshold_high")
    @classmethod
    def high_above_medium(cls, v: float, info) -> float:
        medium = (info.data or {}).get("classifier_threshold_medium", 0.50)
        if v <= medium:
            raise ValueError("classifier_threshold_high must be > classifier_threshold_medium")
        return v


settings = Settings()
