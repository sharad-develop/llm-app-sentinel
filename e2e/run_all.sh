#!/usr/bin/env bash
# Run every e2e script in order against a running server.
# Usage: ./run_all.sh            (defaults to http://localhost:8000)
#        CITADEL_URL=http://host:port ./run_all.sh
set -e
cd "$(dirname "$0")"

for script in [0-9][0-9]_*.sh; do
  echo
  echo "═══════════════════════════════════════════"
  echo "▶ $script"
  echo "═══════════════════════════════════════════"
  bash "$script"
done
