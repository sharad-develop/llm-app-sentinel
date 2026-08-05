#!/usr/bin/env bash
# Clean model output. Expected: allow, safety.safe=true (when Llama Guard
# is loaded; review when it isn't).
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s -X POST "$BASE_URL/v1/output/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "What is the capital of France?",
    "output": "The capital of France is Paris. It has been the capital since 987 AD."
  }' | python3 -m json.tool
