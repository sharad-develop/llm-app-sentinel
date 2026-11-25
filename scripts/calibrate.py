#!/usr/bin/env python
"""Calibrate llm-sentinel's ML thresholds on your own data, with the real models.

    python scripts/calibrate.py leak         # semantic system-prompt-leak threshold (LLM07)
    python scripts/calibrate.py context      # Prompt Guard 2 on documents (LLM01)

Needs the ML extra (``pip install -e ".[ml]"``) and the models (downloaded on
first use). Edit ``scripts/data/*.yaml`` — the closer the cases are to your
production traffic, the better the numbers mean. Exit codes: 0 ok, 1 the data
cannot be separated cleanly at any threshold, 2 a model is unavailable.
"""
import argparse
import statistics
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DATA = Path(__file__).parent / "data"


def suggest_threshold(positives: list[float], negatives: list[float]) -> dict:
    """Pick a threshold separating ``positives`` (to catch) from ``negatives``.

    If every positive scores above every negative, the midpoint of the gap is
    returned (``separable``). Otherwise the candidate with the best F1 wins and
    ``separable`` is False: expect misses or false alarms at any setting.
    """
    if not positives or not negatives:
        raise ValueError("need at least one positive and one negative score")
    lo_pos, hi_neg = min(positives), max(negatives)
    if lo_pos > hi_neg:
        return {
            "threshold": round((lo_pos + hi_neg) / 2, 3), "separable": True,
            "margin": round(lo_pos - hi_neg, 3), "f1": 1.0,
        }
    best = (-1.0, 0.0)
    for t in sorted(set(positives + negatives)):
        tp = sum(p >= t for p in positives)
        fp = sum(n >= t for n in negatives)
        fn = len(positives) - tp
        f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
        if f1 > best[0]:
            best = (f1, t)
    return {"threshold": round(best[1], 3), "separable": False, "margin": 0.0, "f1": round(best[0], 3)}


def rates(scores: list[float], threshold: float) -> float:
    return sum(s >= threshold for s in scores) / len(scores) if scores else 0.0


def describe(label: str, scores: list[float]) -> str:
    if not scores:
        return f"{label}: (none)"
    return (
        f"{label}: n={len(scores)} min={min(scores):.3f} "
        f"median={statistics.median(scores):.3f} max={max(scores):.3f}"
    )


def load_cases(name: str) -> list | dict:
    return yaml.safe_load((DATA / name).read_text(encoding="utf-8"))


# ------------------------------------------------------------------- leak
def calibrate_leak(detector, cases: list[dict], current: float) -> int:
    leaks: list[float] = []
    benign: list[float] = []
    for case in cases:
        for kind, bucket in (("leaks", leaks), ("benign", benign)):
            for text in case.get(kind, []):
                res = detector.score(text, case["system_prompt"])
                if not res.ran:
                    print(f"semantic leak detector unavailable: {res.note}", file=sys.stderr)
                    return 2
                bucket.append(res.similarity)
                print(f"  {res.similarity:.3f}  [{case['id']}/{kind}] {text[:70]}")
    print()
    print(describe("leaks ", leaks))
    print(describe("benign", benign))
    sug = suggest_threshold(leaks, benign)
    print(
        f"\ncurrent threshold {current:.2f}: catches {rates(leaks, current):.0%} of leaks, "
        f"flags {rates(benign, current):.0%} of benign replies"
    )
    t = sug["threshold"]
    print(
        f"suggested threshold {t:.2f} "
        f"({'clean separation, margin ' + str(sug['margin']) if sug['separable'] else 'OVERLAP, best F1 ' + str(sug['f1'])}): "
        f"catches {rates(leaks, t):.0%}, flags {rates(benign, t):.0%}"
    )
    print(f"  -> SENTINEL_SEMANTIC_LEAK_THRESHOLD={t}")
    return 0 if sug["separable"] else 1


# ---------------------------------------------------------------- context
def calibrate_context(classifier, cases: dict, medium: float, high: float) -> int:
    scores = {"benign": [], "attacks": []}
    for kind in scores:
        for text in cases[kind]:
            res = classifier.score(text)
            if not res.ran:
                print(f"classifier unavailable: {res.note}", file=sys.stderr)
                return 2
            scores[kind].append(res.score)
            print(f"  {res.score:.3f}  [{kind}] {text[:70]!r}")
    benign, attacks = scores["benign"], scores["attacks"]
    print()
    print(describe("benign ", benign))
    print(describe("attacks", attacks))
    print(
        f"\ncurrent thresholds medium={medium} high={high}:\n"
        f"  benign  -> review {rates(benign, medium):.0%}, block {rates(benign, high):.0%}\n"
        f"  attacks -> review-or-block {rates(attacks, medium):.0%}, block {rates(attacks, high):.0%}"
    )
    sug = suggest_threshold(attacks, benign)
    print(
        f"suggested single cut-off {sug['threshold']:.2f} "
        f"({'clean separation' if sug['separable'] else 'OVERLAP, best F1 ' + str(sug['f1'])})"
    )
    print("  (use it as `medium`; keep `high` above it, e.g. SENTINEL_CLASSIFIER_THRESHOLD_MEDIUM)")
    return 0 if sug["separable"] else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", choices=["leak", "context"])
    args = ap.parse_args(argv)

    from sentinel.config import settings

    if args.target == "leak":
        from sentinel.pipeline.semantic_leak import SemanticLeakDetector

        det = SemanticLeakDetector()
        det.load()
        return calibrate_leak(det, load_cases("leak_cases.yaml"), settings.semantic_leak_threshold)

    from sentinel.pipeline.classifier import PromptGuardClassifier

    clf = PromptGuardClassifier()
    clf.load()
    return calibrate_context(
        clf, load_cases("context_cases.yaml"),
        settings.classifier_threshold_medium, settings.classifier_threshold_high,
    )


if __name__ == "__main__":
    raise SystemExit(main())
