"""SQL-injection indicator tests (OWASP LLM05)."""
import pytest
import yaml
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.pipeline.output_handling import OutputHandlingPolicy, handle_output
from app.pipeline.sql_guard import detect_sql
from sentinel import Guard, OutputBlocked


class TestDetector:
    @pytest.mark.parametrize("text,expected", [
        ("SELECT * FROM users; DROP TABLE users;", {"sql_destructive", "sql_stacked_statements"}),
        ("admin'; DROP TABLE users;--", {"sql_destructive"}),
        ("SELECT * FROM t WHERE id=1 OR 1=1", {"sql_tautology"}),
        ("x' OR 'a'='a", {"sql_tautology"}),
        ("a' or ''='", {"sql_tautology"}),
        ("SELECT a FROM t UNION ALL SELECT password FROM users", {"sql_union_select"}),
        ("DELETE FROM users", {"sql_unbounded_write"}),
        ("UPDATE users SET admin=1", {"sql_unbounded_write"}),
        ("SELECT name FROM t WHERE id=1 AND SLEEP(5)", {"sql_time_delay"}),
        ("SELECT pg_sleep(10)", {"sql_time_delay"}),
        ("SELECT * INTO OUTFILE '/tmp/x' FROM t", {"sql_file_or_exec"}),
        ("EXEC xp_cmdshell 'dir'", {"sql_file_or_exec"}),
        ("TRUNCATE TABLE logs", {"sql_destructive"}),
        ("GRANT ALL ON db.* TO bob", {"sql_destructive"}),
        ("admin'--", {"sql_comment_truncation"}),
    ])
    def test_flagged(self, text, expected):
        assert set(detect_sql(text)) == expected

    @pytest.mark.parametrize("text", [
        "Update the settings; then drop me a line.",
        "Select an option from the menu",
        "SELECT id, name FROM users WHERE id = 5",
        "DELETE FROM users WHERE id = 3",
        "INSERT INTO t VALUES (1)",
        "SELECT 1 -- note; DROP TABLE y",          # ; inside a comment
        "SELECT 'a;b' FROM t",                     # ; inside a string
        "import time\ntime.sleep(5)",
        "He said \"hello\" -- then left",
        "Create a plan and delete the old files from the server.",
    ])
    def test_not_flagged(self, text):
        assert detect_sql(text) == []

    def test_readonly_flags_writes(self):
        assert "sql_write_statement" in detect_sql("INSERT INTO t VALUES (1)", readonly=True)
        assert "sql_write_statement" in detect_sql("DELETE FROM t WHERE id=1", readonly=True)
        assert "sql_write_statement" in detect_sql("DROP TABLE t", readonly=True)
        assert detect_sql("SELECT a FROM t WHERE id = 1", readonly=True) == []

    def test_sql_inside_prose_and_fences(self):
        text = "Run this:\n```sql\nSELECT 1 FROM t; DROP TABLE t;\n```\nDone."
        assert {"sql_destructive", "sql_stacked_statements"} <= set(detect_sql(text))

    def test_sql_on_line_after_prose_and_in_inline_code(self):
        assert "sql_destructive" in detect_sql("Run this first:\nDROP TABLE users;")
        assert "sql_destructive" in detect_sql("Just run `DROP TABLE users` now")

    def test_two_separate_queries_not_stacked(self):
        text = "```sql\nSELECT a FROM t;\n```\nand\n```sql\nSELECT b FROM u;\n```"
        assert detect_sql(text) == []

    def test_backtick_identifiers_ok(self):
        assert detect_sql("SELECT `a` FROM `t` WHERE `id` = 1") == []


class TestHandling:
    def policy(self, mode):
        return OutputHandlingPolicy(sql=mode)

    def test_default_allows_sql(self):
        r = handle_output("DROP TABLE users;", OutputHandlingPolicy())
        assert not r.blocked and not r.sql_indicators

    def test_block(self):
        r = handle_output("'; DROP TABLE users;--", self.policy("block"))
        assert r.blocked and "sql_destructive" in r.sql_indicators and "sql" in r.findings

    def test_flag_reviews_without_blocking(self):
        r = handle_output("a OR 1=1", self.policy("flag"))
        assert r.review and not r.blocked and r.text == "a OR 1=1"

    def test_readonly_blocks_writes_but_not_selects(self):
        assert handle_output("INSERT INTO t VALUES (1)", self.policy("readonly")).blocked
        assert not handle_output("SELECT a FROM t WHERE id=1", self.policy("readonly")).blocked
        assert not handle_output("INSERT INTO t VALUES (1)", self.policy("block")).blocked

    def test_clean_sql_passes_block_mode(self):
        r = handle_output("SELECT id FROM users WHERE id = 5", self.policy("block"))
        assert not r.blocked and not r.review


class TestPolicyAndSdk:
    def guard(self, tmp_path, mode):
        (tmp_path / "bot.yaml").write_text(yaml.safe_dump({"id": "bot", "output": {"sql": mode}}))
        return Guard(policy_dir=tmp_path)

    def test_block_via_policy(self, tmp_path):
        g = self.guard(tmp_path, "block")
        with pytest.raises(OutputBlocked) as e:
            g.check_output("1; DROP TABLE users", application_id="bot", raise_on_block=True)
        assert e.value.blocked_at == "output_handling"
        out = g.check_output("1; DROP TABLE users", application_id="bot")
        assert out.pipeline.output_handling.sql_indicators == ["sql_destructive"]

    def test_flag_gives_review_verdict(self, tmp_path):
        out = self.guard(tmp_path, "flag").check_output("a OR 1=1", application_id="bot")
        assert out.verdict == "review" and out.sanitized_output == "a OR 1=1"

    def test_other_apps_unaffected(self, tmp_path):
        out = self.guard(tmp_path, "block").check_output("DROP TABLE users")
        assert out.blocked_at is None  # no application_id -> global default (allow)

    def test_env_default(self, monkeypatch):
        monkeypatch.setattr(settings, "output_sql", "block")
        out = Guard().check_output("1; DROP TABLE users")
        assert out.blocked_at == "output_handling"

    def test_invalid_mode_rejected(self, tmp_path):
        g = self.guard(tmp_path, "nope")
        with pytest.raises(ValueError):  # policies load on first use
            g.check_output("hi", application_id="bot")

    def test_rest(self, monkeypatch):
        monkeypatch.setattr(settings, "output_sql", "block")
        with TestClient(app) as c:
            r = c.post("/v1/output/analyze", json={"output": "x'; DROP TABLE users;--"})
            assert r.json()["blocked_at"] == "output_handling"
            assert r.json()["pipeline"]["output_handling"]["sql_indicators"]
