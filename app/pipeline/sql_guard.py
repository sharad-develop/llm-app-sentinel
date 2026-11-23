"""SQL-injection indicators in a model response (OWASP LLM05).

Relevant when a response is executed or interpolated into a SQL query
(text-to-SQL, "generate a filter", an agent with a database tool). Opt-in per
policy because ordinary answers legitimately contain SQL.

Statements are split with sqlparse (it understands quotes and comments, so a
``;`` inside a string or ``-- comment`` is not a statement boundary) and each
is classified by a *shape* regex — "Update the settings" is prose, ``UPDATE
t SET ...`` is SQL. Indicators:

  sql_stacked_statements   two or more SQL statements in one response
  sql_destructive          DROP / TRUNCATE / ALTER / CREATE / GRANT / REVOKE
  sql_unbounded_write      UPDATE or DELETE with no WHERE clause
  sql_write_statement      any INSERT/UPDATE/DELETE (``readonly`` mode only)
  sql_tautology            OR 1=1, OR 'a'='a', ' OR ''='
  sql_union_select         UNION [ALL] SELECT
  sql_comment_truncation   a quote immediately followed by --, # or /* (admin'--)
  sql_time_delay           pg_sleep(), BENCHMARK(), WAITFOR DELAY, AND SLEEP()
  sql_file_or_exec         INTO OUTFILE, LOAD_FILE(), xp_cmdshell, COPY ... PROGRAM

This is heuristic and regex-based, not a SQL validator. It is a backstop: the
real defenses are parameterized queries and a read-only database role.
"""
import re

import sqlparse

_I = re.IGNORECASE | re.DOTALL | re.MULTILINE

_SELECT = re.compile(r"^\s*(?:\(\s*)*select\b.+\bfrom\b|^\s*select\s+(?:\d|['\"(*@])", _I)
_INSERT = re.compile(r"^\s*insert\s+(?:\w+\s+)?into\b", _I)
_UPDATE = re.compile(r"^\s*update\s+\S+\s+set\b", _I)
_DELETE = re.compile(r"^\s*delete\s+from\b", _I)
_DESTRUCTIVE = re.compile(
    r"^\s*(?:"
    r"(?:drop|alter|create)\s+(?:or\s+replace\s+)?(?:temp(?:orary)?\s+)?"
    r"(?:table|database|schema|user|role|index|view|function|procedure|trigger)\b"
    r"|truncate\s+(?:table\s+)?\w"
    r"|(?:grant|revoke)\s+\w[^;]*\b(?:on|to|from)\b"
    r")",
    _I,
)
_WHERE = re.compile(r"\bwhere\b", _I)

_PATTERNS = {
    "sql_tautology": re.compile(
        # closing quote optional: an injected string leaves it for the app to add
        r"""\b(?:or|and)\s+(['"]?)(\w+)\1\s*=\s*\1\2\1?(?!\w)|['"]\s*or\s*['"]{2}\s*=\s*['"]""", _I
    ),
    "sql_union_select": re.compile(r"\bunion\s+(?:all\s+)?select\b", _I),
    "sql_comment_truncation": re.compile(r"""['"](?:--|#|/\*)"""),
    "sql_time_delay": re.compile(
        r"\b(?:pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b"
        r"|(?:\b(?:and|or|select)\b|;|\|\|)\s*\(?\s*sleep\s*\(",
        _I,
    ),
    "sql_file_or_exec": re.compile(
        r"\binto\s+(?:out|dump)file\b|\bload_file\s*\(|\bxp_cmdshell\b"
        r"|\bcopy\b[^;]{0,200}\bprogram\b|\blo_import\s*\(|\bsp_executesql\b",
        _I,
    ),
}


def _kind(stmt: str) -> str | None:
    if _DESTRUCTIVE.search(stmt):
        return "destructive"
    if _DELETE.search(stmt):
        return "delete"
    if _UPDATE.search(stmt):
        return "update"
    if _INSERT.search(stmt):
        return "insert"
    if _SELECT.search(stmt):
        return "select"
    return None


_FENCE_BODY = re.compile(
    r"^[ ]{0,3}(`{3,}|~{3,})[^\n]*\n(.*?)(?:^[ ]{0,3}\1[`~]*[ \t]*$|\Z)",
    re.MULTILINE | re.DOTALL,
)
_INLINE_CODE = re.compile(r"(`+)(?!`)(.+?)(?<!`)\1(?!`)", re.DOTALL)


def _chunks(text: str) -> list[str]:
    """Pieces analysed separately: each fenced block, each inline code span,
    and the surrounding prose. sqlparse reads backticks as quoted identifiers,
    so code must be pulled out before splitting."""
    chunks = [m.group(2) for m in _FENCE_BODY.finditer(text)]
    prose = _FENCE_BODY.sub("\n", text)
    chunks += [m.group(2) for m in _INLINE_CODE.finditer(prose)]
    chunks.append(prose.replace("`", " "))
    return chunks


def detect_sql(text: str, readonly: bool = False) -> list[str]:
    """Return the sorted indicator ids found in ``text`` (empty if none)."""
    found: set[str] = set()

    for chunk in _chunks(text):
        kinds = []
        for stmt in sqlparse.split(chunk):
            k = _kind(stmt)
            if k is None:
                continue
            kinds.append(k)
            if k == "destructive":
                found.add("sql_destructive")
            elif k in ("update", "delete") and not _WHERE.search(stmt):
                found.add("sql_unbounded_write")
            if readonly and k in ("insert", "update", "delete", "destructive"):
                found.add("sql_write_statement")
        # Stacking is judged per chunk: two queries in two code blocks are not
        # one injected payload.
        if len(kinds) >= 2:
            found.add("sql_stacked_statements")

    for name, pattern in _PATTERNS.items():
        if pattern.search(text):
            found.add(name)
    return sorted(found)
