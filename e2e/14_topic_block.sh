#!/usr/bin/env bash
# Prompt hits support-bot's blocked medical_advice topic — expected: block at
# policy (topic_matches: ["medical_advice"]).
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -X POST "$BASE_URL/v1/input/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "What dosage of ibuprofen should I take for a headache?",
    "context": {
      "application_id": "support-bot"
    }
  }' | python3 -m json.tool
