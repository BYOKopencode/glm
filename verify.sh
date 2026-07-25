#!/usr/bin/env bash
# Smoke-tests a RUNNING server. Start it first: python3 main.py
# Usage: ./verify.sh [base_url] [api_key]
set -uo pipefail

BASE="${1:-http://localhost:8000}"
KEY="${2:-}"
AUTH=()
[ -n "$KEY" ] && AUTH=(-H "Authorization: Bearer $KEY")

pass=0
fail=0
check() { # check <label> <expected> <actual>
  if [ "$2" = "$3" ]; then
    echo "  PASS  $1 ($3)"; pass=$((pass+1))
  else
    echo "  FAIL  $1 (expected $2, got $3)"; fail=$((fail+1))
  fi
}

echo "target: $BASE"
echo

echo "[1] health"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/health")
check "GET /health" 200 "$code"

echo
echo "[2] models"
code=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$BASE/v1/models")
check "GET /v1/models" 200 "$code"

echo
echo "[3] CORS preflight -- this is the request that returned 405 before"
hdrs=$(curl -s -i -X OPTIONS "$BASE/v1/chat/completions" \
  -H 'Origin: https://example.com' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: authorization,content-type,x-proxied')
code=$(printf '%s' "$hdrs" | head -n1 | awk '{print $2}')
check "OPTIONS status" 200 "$code"
if printf '%s' "$hdrs" | grep -qi 'access-control-allow-origin'; then
  echo "  PASS  access-control-allow-origin present"; pass=$((pass+1))
else
  echo "  FAIL  access-control-allow-origin MISSING -- CORS middleware not active"; fail=$((fail+1))
fi

echo
echo "[4] malformed JSON should be 400, not 500"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/chat/completions" \
  "${AUTH[@]}" -H 'Content-Type: application/json' -d '{not json')
check "POST bad body" 400 "$code"

echo
echo "[5] unknown model should be a clean error, not a crash"
body=$(curl -s -X POST "$BASE/v1/chat/completions" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"model":"nope-9000","messages":[{"role":"user","content":"hi"}],"stream":false}')
if printf '%s' "$body" | grep -q 'model_not_found'; then
  echo "  PASS  model_not_found returned"; pass=$((pass+1))
else
  echo "  FAIL  unexpected: $body"; fail=$((fail+1))
fi

echo
echo "[6] null content should not 422 (tolerant parsing)"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/chat/completions" \
  "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"model":"glm-4.7","messages":[{"role":"assistant","content":null},{"role":"user","content":[{"type":"text","text":"Say hi."}]}],"stream":false}')
if [ "$code" = "422" ]; then
  echo "  FAIL  got 422 -- strict content typing is back"; fail=$((fail+1))
else
  echo "  PASS  accepted null + array content ($code)"; pass=$((pass+1))
fi

echo
echo "[7] non-streaming completion (launches the browser, may take ~30s)"
body=$(curl -s -X POST "$BASE/v1/chat/completions" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"model":"glm-4.7","messages":[{"role":"user","content":"Say hi in one sentence."}],"stream":false}')
if printf '%s' "$body" | grep -q '"finish_reason":"stop"'; then
  echo "  PASS  completed"; pass=$((pass+1))
else
  echo "  FAIL  $body"; fail=$((fail+1))
fi

echo
echo "[8] streaming"
stream=$(curl -sN --max-time 120 -X POST "$BASE/v1/chat/completions" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"model":"glm-4.7","messages":[{"role":"user","content":"Count to five."}],"stream":true}')
if printf '%s' "$stream" | grep -q 'data: \[DONE\]'; then
  echo "  PASS  stream terminated with [DONE]"; pass=$((pass+1))
else
  echo "  FAIL  no [DONE] sentinel"; fail=$((fail+1))
fi
chunks=$(printf '%s' "$stream" | grep -c '^data: ')
echo "  info  $chunks SSE frames received"

echo
echo "-------------------------------"
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ] || exit 1
