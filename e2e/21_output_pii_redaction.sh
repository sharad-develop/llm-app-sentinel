#!/usr/bin/env bash
# Model response containing PII, vetted under support-bot's policy
# (pii.action: redact). Expected: allow with sanitized_output containing
# [PERSON_1] / [EMAIL_1] placeholders.
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -X POST "$BASE_URL/v1/output/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "output": "The account belongs to John Smith, reachable at john.smith@example.com.",
    "context": { "application_id": "support-bot" }
  }' | python3 -m json.tool
