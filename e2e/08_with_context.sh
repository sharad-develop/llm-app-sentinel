#!/usr/bin/env bash
# Full request with optional context and custom thresholds.
# Context ids show up in the server's audit log lines.
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -X POST "$BASE_URL/v1/input/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "Draft a polite reply to this customer email.",
    "context": {
      "application_id": "support-bot",
      "user_id": "user-42",
      "session_id": "sess-abc123"
    },
    "options": {
      "thresholds": { "medium": 0.30, "high": 0.80 }
    }
  }' | python3 -m json.tool
