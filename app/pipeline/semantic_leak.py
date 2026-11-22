"""Semantic system-prompt leakage detection (OWASP LLM07), optional.

This stage compares *meaning* rather than words: the system prompt and the response are split into
sentence-sized segments, embedded with a sentence-embedding model, and a
response segment whose cosine similarity to any prompt segment reaches the
threshold counts as a restatement — including paraphrases and (with the
default multilingual model) translations.

Opt-in per deployment/call, lazily loaded on first use, never loaded when no
system prompt is supplied. Tune ``SENTINEL_SEMANTIC_LEAK_THRESHOLD``: replies
that legitimately mention a rule ("I can't help with refunds that large") can
score close to the rule itself.
"""
import hashlib
import logging
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable

from app.config import settings

logger = logging.getLogger("llm_sentinel.semantic_leak")

_WORD = re.compile(r"[^\W_]+")
_SPLIT = re.compile(r"(?<=[.!?。！？])\s+|\n+|;\s+")
_MAX_SEGMENT_WORDS = 60
_WINDOW_WORDS = 40
_WINDOW_STRIDE = 30
_CACHE_SIZE = 32

EmbedFn = Callable[[list[str]], list[list[float]]]


@dataclass
class SemanticLeakResult:
    ran: bool
    similarity: float | None = None  # best response-vs-prompt segment cosine
    leaked: bool = False
    note: str | None = None


def split_segments(text: str, min_words: int) -> list[str]:
    """Split into sentence-like segments; long ones become overlapping windows."""
    out: list[str] = []
    for piece in _SPLIT.split(text):
        words = piece.split()
        if len(_WORD.findall(piece)) < min_words:
            continue
        if len(words) <= _MAX_SEGMENT_WORDS:
            out.append(" ".join(words))
            continue
        for i in range(0, len(words), _WINDOW_STRIDE):
            window = words[i : i + _WINDOW_WORDS]
            if len(window) >= min_words:
                out.append(" ".join(window))
            if i + _WINDOW_WORDS >= len(words):
                break
    return out


def _max_similarities(a: list[list[float]], b: list[list[float]]) -> list[float]:
    """For each vector in ``a`` the max dot product against ``b`` (unit vectors)."""
    try:
        import torch

        sims = torch.tensor(a) @ torch.tensor(b).T
        return sims.max(dim=1).values.tolist()
    except ImportError:
        return [max(sum(x * y for x, y in zip(va, vb)) for vb in b) for va in a]


class SemanticLeakDetector:
    def __init__(self, model_name: str | None = None, embed_fn: EmbedFn | None = None):
        self.model_name = model_name or settings.semantic_leak_model
        self._embed_fn = embed_fn  # injectable (tests, custom embedders)
        self._load_attempted = embed_fn is not None
        self._load_error: str | None = None
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, list[list[float]]] = OrderedDict()

    @property
    def available(self) -> bool:
        return self._embed_fn is not None

    def load(self) -> None:
        with self._lock:
            if self._load_attempted:
                return
            self._load_attempted = True
            try:
                import torch
                from transformers import AutoModel, AutoTokenizer

                device = settings.semantic_leak_device
                if device == "auto":
                    device = (
                        "cuda" if torch.cuda.is_available()
                        else "mps" if torch.backends.mps.is_available()
                        else "cpu"
                    )
                try:
                    tok = AutoTokenizer.from_pretrained(self.model_name, local_files_only=True)
                    model = AutoModel.from_pretrained(self.model_name, local_files_only=True)
                except OSError:
                    tok = AutoTokenizer.from_pretrained(self.model_name)
                    model = AutoModel.from_pretrained(self.model_name)
                model = model.to(device).eval()

                def embed(texts: list[str]) -> list[list[float]]:
                    vecs: list[list[float]] = []
                    with torch.no_grad():
                        for i in range(0, len(texts), 32):
                            enc = tok(
                                texts[i : i + 32], padding=True, truncation=True,
                                max_length=128, return_tensors="pt",
                            ).to(device)
                            hidden = model(**enc).last_hidden_state
                            mask = enc["attention_mask"].unsqueeze(-1).to(hidden.dtype)
                            pooled = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
                            pooled = torch.nn.functional.normalize(pooled, dim=1)
                            vecs.extend(pooled.cpu().tolist())
                    return vecs

                self._embed_fn = embed
                logger.info("loaded semantic-leak model %s on %s", self.model_name, device)
            except Exception as exc:  # noqa: BLE001 - any load failure means unavailable
                self._load_error = f"{type(exc).__name__}: {exc}"
                logger.warning("semantic-leak model unavailable: %s", self._load_error)

    def _prompt_vectors(self, segments: list[str], system_prompt: str) -> list[list[float]]:
        # Keyed by hash so the prompt text itself is never retained here.
        key = hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
        vecs = self._embed_fn(segments)
        with self._lock:
            self._cache[key] = vecs
            while len(self._cache) > _CACHE_SIZE:
                self._cache.popitem(last=False)
        return vecs

    def score(self, text: str, system_prompt: str) -> SemanticLeakResult:
        self.load()
        if self._embed_fn is None:
            return SemanticLeakResult(
                ran=False, note=f"semantic_unavailable: {self._load_error}"
            )
        min_words = settings.semantic_leak_min_words
        cap = settings.semantic_leak_max_segments
        prompt_segs = split_segments(system_prompt, min_words)
        out_segs = split_segments(text, min_words)
        if not prompt_segs:
            return SemanticLeakResult(ran=True, note="no_comparable_prompt_segments")
        if not out_segs:
            return SemanticLeakResult(ran=True, similarity=0.0)
        # Not scoring is fail-safe (caller maps ran=False to `review`);
        # truncating would let a leak hide past the cutoff.
        if len(prompt_segs) > cap or len(out_segs) > cap:
            return SemanticLeakResult(
                ran=False,
                note=f"too_many_segments: {len(prompt_segs)}/{len(out_segs)} > {cap}",
            )
        sims = _max_similarities(
            self._embed_fn(out_segs), self._prompt_vectors(prompt_segs, system_prompt)
        )
        best = max(sims)
        return SemanticLeakResult(
            ran=True, similarity=round(best, 4),
            leaked=best >= settings.semantic_leak_threshold,
        )
