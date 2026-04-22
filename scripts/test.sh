#!/usr/bin/env bash
# Smoke tests for whoami.aauth.dev deployment
# Usage: bash scripts/test.sh [base_url]

set -euo pipefail

BASE="${1:-https://whoami.aauth.dev}"
PASS=0
FAIL=0

check() {
  local desc="$1"
  local ok="$2"
  if [ "$ok" = "true" ]; then
    echo "  PASS  $desc"
    ((PASS++))
  else
    echo "  FAIL  $desc"
    ((FAIL++))
  fi
}

echo "Testing $BASE"
echo

# ── .well-known/aauth-resource.json ──
echo "--- /.well-known/aauth-resource.json ---"
RESOURCE_META=$(curl -sf "$BASE/.well-known/aauth-resource.json")

check "issuer matches origin" \
  "$(echo "$RESOURCE_META" | jq -r '.issuer' | grep -qx "$BASE" && echo true || echo false)"

check "jwks_uri present" \
  "$(echo "$RESOURCE_META" | jq -e '.jwks_uri' >/dev/null 2>&1 && echo true || echo false)"

check "scope_descriptions has whoami" \
  "$(echo "$RESOURCE_META" | jq -e '.scope_descriptions.whoami' >/dev/null 2>&1 && echo true || echo false)"

echo

# ── .well-known/jwks.json ──
echo "--- /.well-known/jwks.json ---"
JWKS=$(curl -sf "$BASE/.well-known/jwks.json")

check "has at least one key" \
  "$(echo "$JWKS" | jq -e '.keys | length > 0' 2>/dev/null || echo false)"

check "key is OKP/Ed25519" \
  "$(echo "$JWKS" | jq -e '.keys[0].kty == "OKP" and .keys[0].crv == "Ed25519"' 2>/dev/null || echo false)"

check "key has kid" \
  "$(echo "$JWKS" | jq -e '.keys[0].kid' >/dev/null 2>&1 && echo true || echo false)"

check "no private key material (d)" \
  "$(echo "$JWKS" | jq -e '.keys[0].d == null' 2>/dev/null || echo false)"

echo

# ── GET / with no signature → 401 + Accept-Signature ──
echo "--- GET / (no signature) ---"
RESP=$(curl -sf -o /dev/null -w '%{http_code}' "$BASE/" || true)
check "returns 401" "$([ "$RESP" = "401" ] && echo true || echo false)"

HEADERS=$(curl -sf -D - -o /dev/null "$BASE/" 2>/dev/null || curl -sD - -o /dev/null "$BASE/" 2>/dev/null)
check "has Accept-Signature header" \
  "$(echo "$HEADERS" | grep -qi 'accept-signature' && echo true || echo false)"

echo

# ── GET /?scope=profile with no signature → still 401 + Accept-Signature ──
echo "--- GET /?scope=profile (no signature) ---"
RESP=$(curl -sf -o /dev/null -w '%{http_code}' "$BASE/?scope=profile" || true)
check "returns 401" "$([ "$RESP" = "401" ] && echo true || echo false)"

echo

# ── CORS ──
echo "--- CORS ---"
CORS_HEADERS=$(curl -sf -D - -o /dev/null -X OPTIONS \
  -H "Origin: https://example.com" \
  -H "Access-Control-Request-Method: GET" \
  "$BASE/" 2>/dev/null || true)
check "Access-Control-Allow-Origin present" \
  "$(echo "$CORS_HEADERS" | grep -qi 'access-control-allow-origin' && echo true || echo false)"

echo
echo "========================================="
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "All tests passed!" || echo "Some tests failed."
exit "$FAIL"
