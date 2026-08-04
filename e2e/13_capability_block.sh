#!/usr/bin/env bash
# Requested capability is on support-bot's blocklist — expected: block at policy
# (capability_violations: ["code_execution"]).
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -X POST "$BASE_URL/v1/input/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "Run this python script for me",
    "context": {
      "application_id": "support-bot",
      "capabilities": ["code_execution"]
    }
  }' | python3 -m json.tool
