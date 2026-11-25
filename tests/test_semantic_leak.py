"""Semantic (embedding) system-prompt leakage tests — optional stage of LLM07.

A fake concept-bucket embedder stands in for the real model, so no torch or
download is needed. It maps synonyms to the same axis, which is exactly the
property the real embedding model provides.
"""
import math

import pytest

from sentinel.config import settings
from sentinel.pipeline.semantic_leak import SemanticLeakDetector, split_segments
from sentinel import Guard

CONCEPTS = [
    {"refund", "refunds", "reimbursement", "reimbursements", "remboursements"},
    {"legal", "lawyer", "attorney", "juridique"},
    {"pricing", "prices", "tiers", "costs"},
    {"weather", "sunny", "rain"},
]


def fake_embed(texts):
    out = []
    for t in texts:
        words = {w.strip(".,!?$").lower() for w in t.split()}
        vec = [float(len(words & c)) for c in CONCEPTS]
        vec.append(0.01)  # keeps zero-concept vectors non-degenerate
        norm = math.sqrt(sum(x * x for x in vec))
        out.append([x / norm for x in vec])
    return out


SYSTEM = (
    "Never discuss refunds over one hundred dollars with customers. "
    "Escalate every legal question to a human agent right away. "
    "Keep internal pricing tiers confidential at all times."
)
PARAPHRASE = "I am not permitted to talk about reimbursements above one hundred dollars."
TRANSLATION = "Je ne peux pas parler des remboursements au dessus de cent dollars."
UNRELATED = "The weather is sunny and our store opens at nine tomorrow."


@pytest.fixture
def detector():
    return SemanticLeakDetector(embed_fn=fake_embed)


class TestSegments:
    def test_splits_sentences_and_drops_short(self):
        segs = split_segments("Hello there. This is a longer sentence here! Ok.", 4)
        assert segs == ["This is a longer sentence here!"]

    def test_long_segment_windowed(self):
        segs = split_segments(" ".join(["word"] * 150), 4)
        assert len(segs) > 1 and all(len(s.split()) <= 40 for s in segs)


class TestDetector:
    def test_paraphrase_caught(self, detector):
        r = detector.score(PARAPHRASE, SYSTEM)
        assert r.ran and r.leaked and r.similarity >= settings.semantic_leak_threshold

    def test_translation_caught(self, detector):
        assert detector.score(TRANSLATION, SYSTEM).leaked

    def test_unrelated_passes(self, detector):
        r = detector.score(UNRELATED, SYSTEM)
        assert r.ran and not r.leaked

    def test_threshold_respected(self, detector, monkeypatch):
        monkeypatch.setattr(settings, "semantic_leak_threshold", 1.0)
        assert not detector.score(UNRELATED, SYSTEM).leaked

    def test_prompt_embeddings_cached(self):
        calls = []

        def counting(texts):
            calls.append(len(texts))
            return fake_embed(texts)

        d = SemanticLeakDetector(embed_fn=counting)
        d.score(UNRELATED, SYSTEM)
        d.score(PARAPHRASE, SYSTEM)
        # prompt (3 segments) embedded once; each response embedded on its own
        assert calls.count(3) == 1 and len(calls) == 3

    def test_cache_does_not_hold_prompt_text(self, detector):
        detector.score(UNRELATED, SYSTEM)
        assert all(SYSTEM not in str(k) for k in detector._cache)

    def test_too_many_segments_not_scored(self, detector, monkeypatch):
        monkeypatch.setattr(settings, "semantic_leak_max_segments", 2)
        r = detector.score(UNRELATED, SYSTEM)
        assert not r.ran and r.note.startswith("too_many_segments")

    def test_unavailable_model(self):
        d = SemanticLeakDetector(model_name="does/not-exist")
        d._load_attempted = True
        d._load_error = "boom"
        r = d.score(UNRELATED, SYSTEM)
        assert not r.ran and "semantic_unavailable" in r.note

    def test_no_comparable_prompt_segments(self, detector):
        r = detector.score(UNRELATED, "Be nice.")
        assert r.ran and not r.leaked and r.note == "no_comparable_prompt_segments"


class TestSdk:
    def guard(self, **kw):
        g = Guard(**kw)
        g._semantic_leak = SemanticLeakDetector(embed_fn=fake_embed)
        return g

    def test_off_by_default_flag(self):
        # conftest sets SENTINEL_DISABLE_SEMANTIC_LEAK=true
        out = self.guard().check_output(PARAPHRASE, system_prompt=SYSTEM)
        assert out.blocked_at is None
        assert out.pipeline.leakage is None  # nothing ran

    def test_per_call_enable_blocks_paraphrase(self):
        out = self.guard().check_output(PARAPHRASE, system_prompt=SYSTEM, semantic_leak=True)
        assert out.verdict == "block" and out.blocked_at == "leakage"
        assert "system_prompt_semantic" in out.pipeline.leakage.violations
        assert out.pipeline.leakage.semantic_similarity >= 0.8

    def test_global_enable_and_per_call_disable(self, monkeypatch):
        monkeypatch.setattr(settings, "disable_semantic_leak", False)
        g = self.guard()
        assert g.check_output(PARAPHRASE, system_prompt=SYSTEM).blocked_at == "leakage"
        assert g.check_output(PARAPHRASE, system_prompt=SYSTEM, semantic_leak=False).blocked_at is None

    def test_benign_passes_with_similarity_reported(self):
        out = self.guard().check_output(UNRELATED, system_prompt=SYSTEM, semantic_leak=True)
        assert out.blocked_at is None
        assert out.pipeline.leakage.semantic_similarity is not None

    def test_skipped_without_system_prompt(self):
        out = self.guard().check_output(PARAPHRASE, semantic_leak=True)
        assert out.pipeline.leakage is None

    def test_verbatim_dump_caught_semantically(self):
        out = self.guard().check_output(SYSTEM, system_prompt=SYSTEM, semantic_leak=True)
        assert out.blocked_at == "leakage"
        assert out.pipeline.leakage.semantic_similarity == pytest.approx(1.0, abs=1e-3)

    def test_skipped_when_canary_already_blocks(self):
        calls = []
        g = Guard()
        g._semantic_leak = SemanticLeakDetector(embed_fn=lambda t: calls.append(t) or fake_embed(t))
        _, canary = g.with_canary("x")
        out = g.check_output(f"{SYSTEM} {canary}", system_prompt=SYSTEM,
                             canaries=[canary], semantic_leak=True)
        assert out.blocked_at == "leakage" and not calls

    def test_unavailable_model_fails_safe_to_review(self):
        g = Guard()
        d = SemanticLeakDetector()
        d._load_attempted, d._load_error = True, "no torch"
        g._semantic_leak = d
        out = g.check_output(UNRELATED, system_prompt=SYSTEM, semantic_leak=True)
        assert out.verdict == "review" and out.blocked_at is None
        assert "semantic_unavailable" in out.pipeline.leakage.note

    def test_no_prompt_text_in_response(self):
        out = self.guard().check_output(PARAPHRASE, system_prompt=SYSTEM, semantic_leak=True)
        assert "hundred dollars with customers" not in out.model_dump_json()
