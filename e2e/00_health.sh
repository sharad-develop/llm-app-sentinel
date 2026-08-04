#!/usr/bin/env bash
# Health check — confirms the server is up and whether the classifier loaded.
BASE_URL="${CITADEL_URL:-http://localhost:8000}"

curl -s "$BASE_URL/healthz" | python3 -m json.tool
