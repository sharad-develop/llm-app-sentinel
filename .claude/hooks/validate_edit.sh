#!/usr/bin/env bash
# PostToolUse hook: fast syntax checks on files Claude just edited.
#   *.py              -> py_compile
#   *.yaml / *.yml    -> must parse; rule packs must have compilable regexes
# Exit 2 sends stderr back to Claude so it fixes the problem immediately.
set -euo pipefail

file=$(jq -r '.tool_input.file_path // empty')
[[ -z "$file" || ! -f "$file" ]] && exit 0

cd "${CLAUDE_PROJECT_DIR:-.}"
PY=python3
[[ -x venv/bin/python ]] && PY=venv/bin/python

case "$file" in
  *.py)
    "$PY" -m py_compile "$file" 2>&1 >/dev/null || { echo "py_compile failed for $file" >&2; exit 2; }
    ;;
  *.yaml|*.yml)
    "$PY" - "$file" <<'EOF' || exit 2
import re, sys, yaml
path = sys.argv[1]
try:
    data = yaml.safe_load(open(path, encoding="utf-8"))
except Exception as e:
    sys.exit(print(f"YAML parse error in {path}: {e}", file=sys.stderr) or 1)

# Rule packs: every `pattern` must compile.
if "/rules/" in path and isinstance(data, dict):
    bad = []
    for section, rules in data.items():
        if not isinstance(rules, list):
            continue
        for r in rules:
            if isinstance(r, dict) and "pattern" in r:
                try:
                    re.compile(r["pattern"], re.IGNORECASE)
                except re.error as e:
                    bad.append(f"{section}/{r.get('id', '?')}: {e}")
    if bad:
        print(f"Invalid regex in {path}:\n  " + "\n  ".join(bad), file=sys.stderr)
        sys.exit(1)
EOF
    ;;
esac
exit 0
