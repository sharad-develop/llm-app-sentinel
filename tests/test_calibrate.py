"""scripts/calibrate.py: threshold logic and dataset sanity (no real models)."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("calibrate", ROOT / "scripts" / "calibrate.py")
cal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cal)


class TestSuggestThreshold:
    def test_separable_returns_midpoint(self):
        r = cal.suggest_threshold([0.9, 0.85], [0.4, 0.6])
        assert r == {"threshold": 0.725, "separable": True, "margin": 0.25, "f1": 1.0}

    def test_overlap_picks_best_f1(self):
        r = cal.suggest_threshold([0.9, 0.8, 0.55], [0.6, 0.3, 0.2])
        assert not r["separable"] and 0.55 <= r["threshold"] <= 0.8 and 0 < r["f1"] < 1

    def test_needs_both_classes(self):
        with pytest.raises(ValueError):
            cal.suggest_threshold([], [0.1])

    def test_rates(self):
        assert cal.rates([0.1, 0.5, 0.9], 0.5) == pytest.approx(2 / 3)
        assert cal.rates([], 0.5) == 0.0


class TestDatasets:
    def test_leak_cases_well_formed(self):
        cases = cal.load_cases("leak_cases.yaml")
        assert len(cases) >= 3 and len({c["id"] for c in cases}) == len(cases)
        for c in cases:
            assert c["system_prompt"].strip() and c["leaks"] and c["benign"]
            assert all(isinstance(t, str) and t.strip() for t in c["leaks"] + c["benign"])

    def test_context_cases_well_formed(self):
        cases = cal.load_cases("context_cases.yaml")
        assert len(cases["benign"]) >= 10 and len(cases["attacks"]) >= 10
        assert all(isinstance(t, str) and t.strip() for t in cases["benign"] + cases["attacks"])

    def test_context_attacks_evade_the_regex_rules(self):
        """The classifier calibration is only meaningful if rules don't catch them first."""
        from sentinel.pipeline.context_guard import build_context_rule_engine

        rules = build_context_rule_engine()
        caught = [a for a in cal.load_cases("context_cases.yaml")["attacks"] if not rules.check(a).passed]
        assert caught == []

    def test_context_benign_pass_the_rules(self):
        from sentinel.pipeline.context_guard import build_context_rule_engine

        rules = build_context_rule_engine()
        flagged = [b for b in cal.load_cases("context_cases.yaml")["benign"] if not rules.check(b).passed]
        assert flagged == []


class TestRunners:
    def test_leak_separable_exit_0(self, capsys):
        score = {"leak": 0.9, "ok": 0.3}

        class Det:
            def score(self, text, prompt):
                return SimpleNamespace(ran=True, similarity=score["leak" if "LEAK" in text else "ok"], note=None)

        cases = [{"id": "x", "system_prompt": "p", "leaks": ["LEAK a"], "benign": ["fine"]}]
        assert cal.calibrate_leak(Det(), cases, 0.8) == 0
        out = capsys.readouterr().out
        assert "SENTINEL_SEMANTIC_LEAK_THRESHOLD=0.6" in out

    def test_leak_model_unavailable_exit_2(self):
        class Det:
            def score(self, text, prompt):
                return SimpleNamespace(ran=False, similarity=None, note="semantic_unavailable")

        cases = [{"id": "x", "system_prompt": "p", "leaks": ["a"], "benign": ["b"]}]
        assert cal.calibrate_leak(Det(), cases, 0.8) == 2

    def test_context_overlap_exit_1(self):
        class Clf:
            def score(self, text):
                return SimpleNamespace(ran=True, score=0.6)  # identical for everything

        cases = {"benign": ["a"], "attacks": ["b"]}
        assert cal.calibrate_context(Clf(), cases, 0.5, 0.9) == 1

    def test_context_classifier_unavailable_exit_2(self):
        class Clf:
            def score(self, text):
                return SimpleNamespace(ran=False, score=None, note="classifier_unavailable")

        assert cal.calibrate_context(Clf(), {"benign": ["a"], "attacks": ["b"]}, 0.5, 0.9) == 2
