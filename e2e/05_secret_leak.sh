#!/usr/bin/env bash
# API key in prompt — expected: block at rule_checks (aws_access_key).
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -X POST "$BASE_URL/v1/input/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "Why does my AWS call fail with key AKIAIOSFODNN7EXAMPLE?"
  }' | python3 -m json.tool
