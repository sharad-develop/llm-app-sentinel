#!/usr/bin/env bash
# Unknown field in body — expected: HTTP 422 from request validation.
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -w '\nHTTP %{http_code}\n' -X POST "$BASE_URL/v1/input/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "hello",
    "unexpected_field": "should be rejected"
  }' | python3 -m json.tool 2>/dev/null || true

curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST "$BASE_URL/v1/input/analyze" \
  -H 'Content-Type: application/json' \
  -d '{"prompt": "hello", "unexpected_field": "should be rejected"}'
