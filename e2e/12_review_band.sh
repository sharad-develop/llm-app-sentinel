#!/usr/bin/env bash
# Demonstrates the review verdict: thresholds are lowered so a prompt whose
# score falls between medium and high lands in the review band — the caller
# decides what to do with it. Expected: verdict review, sanitized_prompt present.
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -X POST "$BASE_URL/v1/input/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "What is the capital of France?",
    "options": {
      "thresholds": { "medium": 0.0001, "high": 0.5 }
    }
  }' | python3 -m json.tool
