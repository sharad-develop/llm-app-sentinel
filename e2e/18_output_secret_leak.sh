#!/usr/bin/env bash
# Model response leaking an API key. Expected: block at rule_checks
# (openai_key), sanitized_output withheld.
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -X POST "$BASE_URL/v1/output/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "output": "Sure! Use this key in your script: sk-proj4bcdEfGhIjKlMnOpQrStUvWx"
  }' | python3 -m json.tool
