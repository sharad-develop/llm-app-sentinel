#!/usr/bin/env bash
# Prompt contains an email and phone number — support-bot's policy action is
# redact. Expected: allow, sanitized_prompt has [EMAIL_1]/[PHONE_1]
# placeholders, pipeline.policy.pii.found lists the types.
# Requires the PII model to be loaded (first run downloads it).
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -X POST "$BASE_URL/v1/input/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "Draft a reply to John Smith at john.smith@example.com, phone 415-555-0132, about his refund.",
    "context": {
      "application_id": "support-bot"
    }
  }' | python3 -m json.tool
