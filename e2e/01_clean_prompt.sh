#!/usr/bin/env bash
# Clean prompt — expected verdict: allow (or review if classifier isn't loaded).
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -X POST "$BASE_URL/v1/input/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "What is the capital of France?"
  }' | python3 -m json.tool
