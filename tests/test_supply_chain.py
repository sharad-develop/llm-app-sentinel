"""LLM03: model revision pinning and supply-chain hygiene."""
import importlib.util
import re
import sys
import types
from pathlib import Path

import pytest

from sentinel.config import settings
from sentinel.pipeline.model_pin import resolve_revision
from sentinel.pipeline.pii import PIIDetector

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


class TestResolveRevision:
    def test_unpinned_allowed_by_default(self):
        assert resolve_revision("org/m", "") is None
        assert resolve_revision("org/m", None) is None

    def test_pinned_passthrough(self):
        assert resolve_revision("org/m", f" {SHA} ") == SHA

    def test_require_pinned_rejects_missing(self, monkeypatch):
        monkeypatch.setattr(settings, "require_pinned_models", True)
        with pytest.raises(ValueError, match="pinned"):
            resolve_revision("org/m", "")

    @pytest.mark.parametrize("rev", ["main", "v1.0", "abc123", "A" * 40, "g" * 40, "a" * 39])
    def test_require_pinned_rejects_mutable_refs(self, monkeypatch, rev):
        monkeypatch.setattr(settings, "require_pinned_models", True)
        with pytest.raises(ValueError):
            resolve_revision("org/m", rev)

    def test_require_pinned_accepts_commit(self, monkeypatch):
        monkeypatch.setattr(settings, "require_pinned_models", True)
        assert resolve_revision("org/m", SHA) == SHA


class FakeTransformers(types.ModuleType):
    """Records the kwargs every from_pretrained call receives."""

    def __init__(self):
        super().__init__("transformers")
        self.calls: list[dict] = []
        calls = self.calls

        class Loadable:
            @classmethod
            def from_pretrained(cls, name, **kw):
                calls.append({"name": name, **kw})
                return cls()

        self.AutoTokenizer = type("AutoTokenizer", (Loadable,), {})
        self.AutoModelForTokenClassification = type("AutoModelForTokenClassification", (Loadable,), {})
        self.pipeline = lambda *a, **kw: object()


class TestLoadersPassRevision:
    @pytest.fixture()
    def fake(self, monkeypatch):
        fake = FakeTransformers()
        monkeypatch.setitem(sys.modules, "transformers", fake)
        monkeypatch.setattr(settings, "disable_pii", False)
        return fake

    def test_pii_models_get_their_own_revision(self, fake, monkeypatch):
        monkeypatch.setattr(settings, "pii_revision", "1" * 40)
        monkeypatch.setattr(settings, "pii_ner_revision", "2" * 40)
        d = PIIDetector(model_name="org/pii", ner_model_name="org/ner")
        d.load()
        assert d.available
        by_name = {c["name"]: c["revision"] for c in fake.calls}
        assert by_name == {"org/pii": "1" * 40, "org/ner": "2" * 40}
        assert all(c["trust_remote_code"] is False for c in fake.calls)

    def test_require_pinned_makes_unpinned_model_unavailable(self, fake, monkeypatch):
        monkeypatch.setattr(settings, "require_pinned_models", True)
        monkeypatch.setattr(settings, "pii_revision", "")
        d = PIIDetector(model_name="org/pii", ner_model_name="")
        d.load()
        assert not d.available and "pinned" in d.load_error
        assert fake.calls == []  # nothing was fetched


def test_never_trust_remote_code():
    """Loading a model must never execute code shipped with the model repo."""
    offenders = [
        str(p.relative_to(ROOT))
        for p in (ROOT / "sentinel").rglob("*.py")
        if re.search(r"trust_remote_code\s*=\s*True", p.read_text())
    ]
    assert offenders == []


def test_every_from_pretrained_is_pinnable():
    """All model loads use the centralized pinned loader."""
    for p in (ROOT / "sentinel" / "pipeline").glob("*.py"):
        if p.name == "model_loading.py":
            continue
        src = p.read_text()
        calls = len(re.findall(r"from_pretrained\(", src))
        pinned = len(re.findall(r"revision=", src))
        assert calls == 0 or pinned >= calls, f"{p.name}: {calls} loads, {pinned} revisions"

    loader = (ROOT / "sentinel" / "pipeline" / "model_loading.py").read_text()
    assert '"revision": resolved' in loader
    assert '"trust_remote_code": False' in loader


class TestPinScript:
    @pytest.fixture()
    def mod(self):
        spec = importlib.util.spec_from_file_location("pin_models", ROOT / "scripts" / "pin_models.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def test_reads_refs_main(self, mod, tmp_path):
        ref = tmp_path / "models--org--name" / "refs"
        ref.mkdir(parents=True)
        (ref / "main").write_text(SHA + "\n")
        assert mod.cached_revision("org/name", tmp_path) == SHA
        assert mod.cached_revision("org/other", tmp_path) is None

    def test_ignores_malformed_ref(self, mod, tmp_path):
        ref = tmp_path / "models--org--name" / "refs"
        ref.mkdir(parents=True)
        (ref / "main").write_text("not-a-sha")
        assert mod.cached_revision("org/name", tmp_path) is None
