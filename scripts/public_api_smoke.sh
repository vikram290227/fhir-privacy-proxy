#!/usr/bin/env bash
# Smoke test: fetch real Patient resources from the public HAPI FHIR
# sandbox (via the proxy) and verify role-based redaction.
#
# Prerequisites:
#   - The stack is running with FHIR_UPSTREAM=http://hapi.fhir.org/baseR4
#   - Keycloak is up and realm hospital-a has nurse1, doctor1, admin1
#
# Usage: ./scripts/public_api_smoke.sh
#   PROXY_URL      (default http://localhost:8080)
#   FHIR_PUBLIC    (default http://hapi.fhir.org/baseR4)
#   PATIENT_COUNT  (default 5)

set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8080}"
FHIR_PUBLIC="${FHIR_PUBLIC:-http://hapi.fhir.org/baseR4}"
PATIENT_COUNT="${PATIENT_COUNT:-5}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

color() { printf "\033[1;%dm%s\033[0m\n" "$1" "$2"; }
title() { echo; color 34 "=== $* ==="; }
ok()    { color 32 "  ✓ $*"; }
fail()  { color 31 "  ✗ $*"; }
dim()   { color 90 "    $*"; }

PASS=0
FAIL=0

assert_field() {
    local role="$1" pid="$2" field="$3" expected="$4" actual="$5"
    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS + 1))
    else
        fail "${role} Patient/${pid} ${field}: expected ${expected}, got ${actual}"
        FAIL=$((FAIL + 1))
    fi
}

# -----------------------------------------------------------
# Step 1 — Verify metadata endpoint (unauthenticated)
# -----------------------------------------------------------
title "Metadata endpoint (no auth required)"
META_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/fhir/r4/metadata" \
    -H "Accept: application/fhir+json")
if [ "$META_CODE" = "200" ]; then
    ok "GET /fhir/r4/metadata returned 200"
    PASS=$((PASS + 1))

    META_BODY=$(curl -s "${PROXY_URL}/fhir/r4/metadata" -H "Accept: application/fhir+json")
    META_RT=$(echo "$META_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('resourceType',''))" 2>/dev/null || echo "")
    if [ "$META_RT" = "CapabilityStatement" ]; then
        ok "resourceType = CapabilityStatement"
        PASS=$((PASS + 1))
    else
        fail "resourceType = ${META_RT}, expected CapabilityStatement"
        FAIL=$((FAIL + 1))
    fi

    META_URL=$(echo "$META_BODY" | python3 -c "
import sys, json
d = json.load(sys.stdin)
impl = d.get('implementation', {})
print(impl.get('url', d.get('url', '')))
" 2>/dev/null || echo "")
    if echo "$META_URL" | grep -q "localhost:8080"; then
        ok "implementation.url rewritten to proxy"
        PASS=$((PASS + 1))
    else
        fail "implementation.url not rewritten: ${META_URL}"
        FAIL=$((FAIL + 1))
    fi
else
    fail "GET /fhir/r4/metadata returned ${META_CODE}"
    FAIL=$((FAIL + 1))
fi

# -----------------------------------------------------------
# Step 2 — Fetch patient IDs from the public HAPI server
# -----------------------------------------------------------
title "Fetching ${PATIENT_COUNT} Patient IDs from public HAPI"
PATIENT_IDS=$(curl -s "${FHIR_PUBLIC}/Patient?_count=${PATIENT_COUNT}&_elements=id" \
    -H "Accept: application/fhir+json" | \
    python3 -c "
import sys, json
bundle = json.load(sys.stdin)
entries = bundle.get('entry', [])
for e in entries:
    r = e.get('resource', {})
    pid = r.get('id', '')
    if pid:
        print(pid)
" 2>/dev/null)

if [ -z "$PATIENT_IDS" ]; then
    fail "Could not fetch patient IDs from ${FHIR_PUBLIC}"
    echo "  Make sure ${FHIR_PUBLIC} is reachable."
    exit 1
fi

ID_COUNT=$(echo "$PATIENT_IDS" | wc -l | tr -d ' ')
ok "Got ${ID_COUNT} patient IDs"

# -----------------------------------------------------------
# Step 3 — Get tokens for all three roles
# -----------------------------------------------------------
title "Fetching tokens from Keycloak"
NURSE_TOKEN=$("$SCRIPT_DIR/get_token.sh" nurse1 password)
DOCTOR_TOKEN=$("$SCRIPT_DIR/get_token.sh" doctor1 password)
ADMIN_TOKEN=$("$SCRIPT_DIR/get_token.sh" admin1 password)
ok "Got tokens for nurse1 / doctor1 / admin1"

# -----------------------------------------------------------
# Step 4 — Query each patient through the proxy with each role
# -----------------------------------------------------------
title "Querying patients through proxy — verifying redaction"

check_field() {
    local body="$1" field="$2"
    python3 -c "
import sys, json
d = json.loads('''$body''')
if '$field' not in d:
    print('REMOVED')
elif d['$field'] == '***REDACTED***':
    print('MASKED')
else:
    print('VISIBLE')
" 2>/dev/null || echo "ERROR"
}

printf "\n  %-12s %-14s %-12s %-12s %-12s\n" "ROLE" "PATIENT" "identifier" "telecom" "address"
printf "  %-12s %-14s %-12s %-12s %-12s\n" "----" "-------" "----------" "-------" "-------"

for PID in $PATIENT_IDS; do
    for ROLE_INFO in "nurse:${NURSE_TOKEN}:REMOVED:MASKED:MASKED" \
                     "doctor:${DOCTOR_TOKEN}:VISIBLE:VISIBLE:MASKED" \
                     "admin:${ADMIN_TOKEN}:VISIBLE:VISIBLE:VISIBLE"; do
        ROLE=$(echo "$ROLE_INFO" | cut -d: -f1)
        TOKEN=$(echo "$ROLE_INFO" | cut -d: -f2)
        EXPECT_ID=$(echo "$ROLE_INFO" | cut -d: -f3)
        EXPECT_TEL=$(echo "$ROLE_INFO" | cut -d: -f4)
        EXPECT_ADDR=$(echo "$ROLE_INFO" | cut -d: -f5)

        RESP=$(curl -s -w "\n%{http_code}" \
            "${PROXY_URL}/fhir/r4/Patient/${PID}" \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Accept: application/fhir+json" 2>/dev/null)

        CODE=$(echo "$RESP" | tail -1)
        BODY=$(echo "$RESP" | sed '$d')

        if [ "$CODE" != "200" ]; then
            printf "  %-12s %-14s HTTP %s\n" "$ROLE" "$PID" "$CODE"
            continue
        fi

        ACT_ID=$(check_field "$BODY" "identifier")
        ACT_TEL=$(check_field "$BODY" "telecom")
        ACT_ADDR=$(check_field "$BODY" "address")

        printf "  %-12s %-14s %-12s %-12s %-12s" "$ROLE" "$PID" "$ACT_ID" "$ACT_TEL" "$ACT_ADDR"

        assert_field "$ROLE" "$PID" "identifier" "$EXPECT_ID" "$ACT_ID"
        assert_field "$ROLE" "$PID" "telecom"    "$EXPECT_TEL" "$ACT_TEL"
        assert_field "$ROLE" "$PID" "address"    "$EXPECT_ADDR" "$ACT_ADDR"
        echo ""
    done
done

# -----------------------------------------------------------
# Summary
# -----------------------------------------------------------
title "Results"
ok "Passed: ${PASS}"
if [ "$FAIL" -gt 0 ]; then
    fail "Failed: ${FAIL}"
    exit 1
else
    ok "All assertions passed"
fi
