#!/usr/bin/env bash
# Null byte in prompt (JSON \u0000 escape) - expected: HTTP 422.
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -w '\nHTTP %{http_code}\n' -X POST "$BASE_URL/v1/input/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "hello\u0000world"
  }'
echo
