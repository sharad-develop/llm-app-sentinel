"""Tool-call guard for agents (OWASP LLM06 — excessive agency).

When a model can call tools, its output is a command. Before the agent
executes one, ``check_tool_call`` validates the call against the
application's policy (``tools:`` section). It is deny-by-default:

  * the tool must be listed, otherwise ``tool_not_allowed`` (blocked)
  * only declared arguments are accepted; unknown ones are blocked
  * every argument is type-, length-, pattern- and enum-checked
  * ``kind`` adds a semantic check for risky argument types:
      ``path``   — absolute, no traversal, inside the declared ``roots``
      ``url``    — http(s) only, no credentials, no private/loopback/metadata
                   hosts (SSRF); optional ``allowed_domains``
      ``sql``    — read-only by default (``readonly: false`` to allow writes)
      ``shell``  — no shell metacharacters
  * secrets in arguments (known key formats; entropy unless a ``pattern`` or
    ``enum`` pins the value) are blocked — a tool call is an exfiltration path
  * ``confirm: true`` turns an otherwise-valid call into ``review`` so a human
    approves destructive or outward-facing actions

Violations name the argument, never its value.

Limits: this validates what the model *asked for*. It cannot see symlinks,
DNS rebinding, or what the tool does internally. Keep least privilege at the
tool itself (scoped credentials, ``subprocess`` without ``shell=True``,
parameterized queries); treat this as a gate, not the sandbox.
"""
import ipaddress
import json
import math
import posixpath
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from sentinel.config import settings
from sentinel.pipeline.secret_scan import find_secrets
from sentinel.pipeline.sql_guard import detect_sql

_TYPES = {"string", "integer", "number", "boolean"}
_KINDS = {"path", "url", "sql", "shell"}
_TOOL_KEYS = {"confirm", "args"}
_ARG_KEYS = {
    "type", "required", "max_length", "pattern", "enum", "kind", "roots",
    "allowed_domains", "readonly", "minimum", "maximum",
}
_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SHELL_META = set(";&|`$<>\n\r\\(){}")
_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*$")
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".lan")


@dataclass
class ToolDecision:
    verdict: str = "allow"  # allow | review | block
    tool: str = ""
    violations: list[str] = field(default_factory=list)
    requires_confirmation: bool = False


# ------------------------------------------------------------- validation
def validate_tools_section(name: str, section: object, where: str = "tools") -> None:
    """Validate a policy file's ``tools:`` section (raises ValueError)."""
    def bad(msg: str) -> ValueError:
        return ValueError(f"policy {name!r}: {where}{msg}")

    if not isinstance(section, dict):
        raise bad(" must be a mapping")
    if set(section) - {"allowed"}:
        raise bad(f" has unknown keys {sorted(set(section) - {'allowed'})}")
    allowed = section.get("allowed")
    allowed = {} if allowed is None else allowed
    if not isinstance(allowed, dict):
        raise bad(".allowed must be a mapping of tool name -> spec")
    for tool, spec in allowed.items():
        if not isinstance(tool, str) or not _TOOL_NAME.match(tool):
            raise bad(f".allowed has an invalid tool name {tool!r}")
        spec = {} if spec is None else spec
        if not isinstance(spec, dict) or set(spec) - _TOOL_KEYS:
            raise bad(f".allowed[{tool!r}] must be a mapping with keys {sorted(_TOOL_KEYS)}")
        if not isinstance(spec.get("confirm", False), bool):
            raise bad(f".allowed[{tool!r}].confirm must be a boolean")
        args = spec.get("args")
        args = {} if args is None else args
        if not isinstance(args, dict):
            raise bad(f".allowed[{tool!r}].args must be a mapping")
        for arg, a in args.items():
            _validate_arg(name, f"{where}.allowed[{tool!r}].args[{arg!r}]", a)


def _validate_arg(name: str, path: str, a: object) -> None:
    def bad(msg: str) -> ValueError:
        return ValueError(f"policy {name!r}: {path}{msg}")

    a = {} if a is None else a
    if not isinstance(a, dict) or set(a) - _ARG_KEYS:
        raise bad(f" must be a mapping with keys {sorted(_ARG_KEYS)}")
    if a.get("type", "string") not in _TYPES:
        raise bad(f".type must be one of {sorted(_TYPES)}")
    kind = a.get("kind")
    if kind is not None:
        if kind not in _KINDS:
            raise bad(f".kind must be one of {sorted(_KINDS)}")
        if a.get("type", "string") != "string":
            raise bad(f".kind {kind!r} requires type string")
    if "pattern" in a:
        try:
            re.compile(a["pattern"])
        except (re.error, TypeError) as exc:
            raise bad(f".pattern is not a valid regex: {exc}") from exc
    if "enum" in a and (not isinstance(a["enum"], list) or not a["enum"]):
        raise bad(".enum must be a non-empty list")
    if "max_length" in a and (
        not isinstance(a["max_length"], int) or isinstance(a["max_length"], bool) or a["max_length"] < 1
    ):
        raise bad(".max_length must be a positive integer")
    for key in ("minimum", "maximum"):
        if key in a and (not isinstance(a[key], (int, float)) or isinstance(a[key], bool)):
            raise bad(f".{key} must be a number")
    if "required" in a and not isinstance(a["required"], bool):
        raise bad(".required must be a boolean")
    if "readonly" in a and not isinstance(a["readonly"], bool):
        raise bad(".readonly must be a boolean")
    if kind == "path":
        roots = a.get("roots")
        if (
            not isinstance(roots, list) or not roots
            or not all(isinstance(r, str) and r.startswith("/") for r in roots)
        ):
            raise bad(".roots must be a non-empty list of absolute paths for kind 'path'")
    domains = a.get("allowed_domains")
    if domains is not None and (
        kind != "url" or not isinstance(domains, list) or not all(isinstance(d, str) for d in domains)
    ):
        raise bad(".allowed_domains must be a list of strings and requires kind 'url'")


# ----------------------------------------------------------- kind checks
def _path_ok(value: str, roots: list[str]) -> bool:
    v = unquote(value)
    if "\x00" in v or "\\" in v or not v.startswith("/"):
        return False
    if ".." in v.split("/"):
        return False
    norm = posixpath.normpath(v)
    normalized = [posixpath.normpath(r) for r in roots]
    return any(norm == r or norm.startswith(r.rstrip("/") + "/") for r in normalized)


def _host_blocked(host: str) -> bool:
    """True for hosts a model-chosen URL must never reach (SSRF)."""
    if _NUMERIC_HOST.match(host):
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return True  # decimal/hex/octal obfuscation such as 2130706433
        return _ip_blocked(ip)
    try:
        return _ip_blocked(ipaddress.ip_address(host))
    except ValueError:
        pass
    return host == "localhost" or host.endswith(_LOCAL_SUFFIXES)


def _ip_blocked(ip: ipaddress._BaseAddress) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return not ip.is_global


def _url_ok(value: str, domains: list[str] | None) -> bool:
    try:
        parts = urlsplit(value)
        _ = parts.port
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or parts.username or parts.password:
        return False
    host = (parts.hostname or "").lower().rstrip(".")
    if not host or _host_blocked(host):
        return False
    if domains:
        return any(host == d.lower() or host.endswith("." + d.lower()) for d in domains)
    return True


def _shell_ok(value: str) -> bool:
    return not (_SHELL_META & set(value))


# ------------------------------------------------------------- the check
def _check_arg(name: str, value: object, spec: dict, secret_rules) -> list[str]:
    tag = name[:64]
    typ = spec.get("type", "string")
    ok = {
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool)
        and math.isfinite(value),
        "boolean": isinstance(value, bool),
    }[typ]
    if not ok:
        return [f"arg_type:{tag}"]

    if typ in ("integer", "number"):
        if ("minimum" in spec and value < spec["minimum"]) or (
            "maximum" in spec and value > spec["maximum"]
        ):
            return [f"arg_range:{tag}"]
    if "enum" in spec and value not in spec["enum"]:
        return [f"arg_enum:{tag}"]
    if typ != "string":
        return []

    out: list[str] = []
    if len(value) > spec.get("max_length", settings.tool_arg_max_length):
        return [f"arg_too_long:{tag}"]
    if _CONTROL.search(value):
        return [f"arg_control_chars:{tag}"]
    if "pattern" in spec and not re.fullmatch(spec["pattern"], value):
        out.append(f"arg_pattern:{tag}")

    pinned = "pattern" in spec or "enum" in spec
    if secret_rules is not None and any(r.pattern.search(value) for r in secret_rules):
        out.append(f"arg_secret:{tag}")
    elif not pinned and find_secrets(value):
        out.append(f"arg_secret:{tag}")

    kind = spec.get("kind")
    if kind == "path" and not _path_ok(value, spec["roots"]):
        out.append(f"arg_path:{tag}")
    elif kind == "url" and not _url_ok(value, spec.get("allowed_domains")):
        out.append(f"arg_url:{tag}")
    elif kind == "shell" and not _shell_ok(value):
        out.append(f"arg_shell:{tag}")
    elif kind == "sql":
        out += [
            f"arg_sql:{tag}:{ind}"
            for ind in detect_sql(value, readonly=spec.get("readonly", True))
        ]
    return out


def check_tool_call(
    tool: str,
    arguments: object,
    tools: dict | None,
    rule_engine=None,
) -> ToolDecision:
    """Validate one tool call against a policy ``tools:`` section.

    ``tools=None`` means the application has no tool policy: everything is
    denied. ``rule_engine`` (optional) contributes its ``secret_patterns``.
    """
    dec = ToolDecision(tool=tool[:128] if isinstance(tool, str) else "")

    def block(*violations: str) -> ToolDecision:
        dec.verdict = "block"
        dec.violations += violations
        return dec

    if tools is None:
        return block("no_tool_policy")
    if not isinstance(tool, str) or not _TOOL_NAME.match(tool):
        return block("tool_name_invalid")
    spec = (tools.get("allowed") or {}).get(tool)
    if spec is None and tool not in (tools.get("allowed") or {}):
        return block("tool_not_allowed")
    spec = spec or {}
    if not isinstance(arguments, dict):
        return block("args_not_object")
    try:
        size = len(json.dumps(arguments, default=str))
    except (TypeError, ValueError):
        return block("args_not_serializable")
    if size > settings.tool_max_args_bytes:
        return block("args_too_large")

    arg_specs = spec.get("args") or {}
    secret_rules = (
        [r for r in rule_engine.rules if r.category == "secret_patterns"]
        if rule_engine is not None else None
    )
    for arg in arguments:
        if arg not in arg_specs:
            dec.violations.append(f"arg_unknown:{str(arg)[:64]}")
    for arg, a in arg_specs.items():
        a = a or {}
        if arg not in arguments:
            if a.get("required", False):
                dec.violations.append(f"arg_missing:{arg}")
            continue
        dec.violations += _check_arg(arg, arguments[arg], a, secret_rules)

    if dec.violations:
        dec.verdict = "block"
    elif spec.get("confirm", False):
        dec.verdict = "review"
        dec.requires_confirmation = True
    return dec
