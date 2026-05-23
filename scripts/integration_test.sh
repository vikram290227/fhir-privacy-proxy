#!/bin/bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
PASS=0
FAIL=0

check() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if [ "$actual" = "$expected" ]; then
        echo "  ✅ $desc"
        PASS=$((PASS+1))
    else
        echo "  ❌ $desc (expected=$expected, got=$actual)"
        FAIL=$((FAIL+1))
    fi
}

echo "=== Health Check ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/health")
check "GET /health returns 200" "200" "$STATUS"

echo "=== No Token ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/fhir/r4/Patient/1")
check "No token returns 401" "401" "$STATUS"

echo "=== Invalid Token ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer invalid.token.here" \
  "$BASE_URL/fhir/r4/Patient/1")
check "Bad token returns 401" "401" "$STATUS"

echo "=== Nurse Access ==="
TOKEN=$(./scripts/get_token.sh nurse1 password | jq -r .access_token)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/fhir/r4/Patient/test-patient-1")
check "Nurse access returns 200 or 404 (not 401/403)" "200|404" "$(echo $STATUS | grep -cP '200|404' || echo $STATUS)"

echo "=== Telecom Redaction (nurse outside ED) ==="
BODY=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/fhir/r4/Patient/test-patient-1")
HAS_TELECOM=$(echo "$BODY" | jq 'has("telecom")' 2>/dev/null || echo "error")
check "Nurse response has no telecom field" "false" "$HAS_TELECOM"

echo "=== Break-Glass without header ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Break-Glass: true" \
  "$BASE_URL/fhir/r4/Patient/test-patient-1")
# nurse1 has can_break_glass role but needs justification
check "Break-glass without justification returns 400" "400" "$STATUS"

echo "=== Break-Glass with valid header ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Break-Glass: true" \
  -H "X-Break-Glass-Justification: Patient arrived unconscious in ER, need medication history" \
  "$BASE_URL/fhir/r4/Patient/test-patient-1")
check "Valid break-glass returns 200 or 404" "200|404" "$(echo $STATUS | grep -cP '200|404' || echo $STATUS)"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && exit 0 || exit 1
