#!/usr/bin/env bash
# End-to-end test: create a Patient on HAPI FHIR, then query through the proxy.
# Usage: ./scripts/test_patient.sh
#
# Prerequisites: docker-compose services running (make up)
#   - HAPI FHIR on :8090
#   - Keycloak on :8180 (with realm imported)
#   - OPA on :8181
#   - Proxy on :8080

set -euo pipefail

FHIR_DIRECT="${FHIR_DIRECT:-http://localhost:8090/fhir}"
PROXY_URL="${PROXY_URL:-http://localhost:8080}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Step 1: Create Patient directly on HAPI FHIR ==="

PATIENT_RESPONSE=$(curl -s -X POST "${FHIR_DIRECT}/Patient" \
  -H "Content-Type: application/fhir+json" \
  -d '{
    "resourceType": "Patient",
    "identifier": [
      { "system": "http://hospital-a.local/mrn", "value": "MRN-12345" },
      { "system": "http://hl7.org/fhir/sid/us-ssn", "value": "999-00-1234" }
    ],
    "name": [{ "family": "Smith", "given": ["John"] }],
    "telecom": [
      { "system": "phone", "value": "555-0123" },
      { "system": "email", "value": "john.smith@example.com" }
    ],
    "address": [
      { "line": ["123 Main St"], "city": "Springfield", "state": "IL", "postalCode": "62701" }
    ],
    "gender": "male",
    "birthDate": "1985-03-15"
  }')

PATIENT_ID=$(echo "$PATIENT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)

if [ -z "$PATIENT_ID" ]; then
  echo "ERROR: Failed to create patient"
  echo "$PATIENT_RESPONSE"
  exit 1
fi

echo "  Created Patient/${PATIENT_ID}"
echo ""

echo "=== Step 2: Get token for nurse1 ==="
NURSE_TOKEN=$("$SCRIPT_DIR/get_token.sh" nurse1 password)
echo "  Got nurse1 token (${#NURSE_TOKEN} chars)"
echo ""

echo "=== Step 3: Query Patient through proxy as nurse1 ==="
echo "  GET ${PROXY_URL}/fhir/r4/Patient/${PATIENT_ID}"
echo ""

NURSE_RESPONSE=$(curl -s -w "\n%{http_code}" \
  "${PROXY_URL}/fhir/r4/Patient/${PATIENT_ID}" \
  -H "Authorization: Bearer ${NURSE_TOKEN}" \
  -H "Accept: application/fhir+json")

NURSE_HTTP_CODE=$(echo "$NURSE_RESPONSE" | tail -1)
NURSE_BODY=$(echo "$NURSE_RESPONSE" | sed '$d')

echo "  HTTP ${NURSE_HTTP_CODE}"
if [ "$NURSE_HTTP_CODE" = "200" ]; then
  echo "  Response (nurse1 — expect identifier removed, telecom+address masked):"
  echo "$NURSE_BODY" | python3 -m json.tool 2>/dev/null || echo "$NURSE_BODY"
else
  echo "  Response:"
  echo "$NURSE_BODY" | python3 -m json.tool 2>/dev/null || echo "$NURSE_BODY"
fi
echo ""

echo "=== Step 4: Get token for doctor1 ==="
DOCTOR_TOKEN=$("$SCRIPT_DIR/get_token.sh" doctor1 password)
echo "  Got doctor1 token (${#DOCTOR_TOKEN} chars)"
echo ""

echo "=== Step 5: Query Patient through proxy as doctor1 ==="
echo "  GET ${PROXY_URL}/fhir/r4/Patient/${PATIENT_ID}"
echo ""

DOCTOR_RESPONSE=$(curl -s -w "\n%{http_code}" \
  "${PROXY_URL}/fhir/r4/Patient/${PATIENT_ID}" \
  -H "Authorization: Bearer ${DOCTOR_TOKEN}" \
  -H "Accept: application/fhir+json")

DOCTOR_HTTP_CODE=$(echo "$DOCTOR_RESPONSE" | tail -1)
DOCTOR_BODY=$(echo "$DOCTOR_RESPONSE" | sed '$d')

echo "  HTTP ${DOCTOR_HTTP_CODE}"
if [ "$DOCTOR_HTTP_CODE" = "200" ]; then
  echo "  Response (doctor1 — expect identifier present, address masked):"
  echo "$DOCTOR_BODY" | python3 -m json.tool 2>/dev/null || echo "$DOCTOR_BODY"
else
  echo "  Response:"
  echo "$DOCTOR_BODY" | python3 -m json.tool 2>/dev/null || echo "$DOCTOR_BODY"
fi
echo ""

echo "=== Step 6: Test break-glass as nurse1 ==="

BREAKGLASS_RESPONSE=$(curl -s -w "\n%{http_code}" \
  "${PROXY_URL}/fhir/r4/Patient/${PATIENT_ID}" \
  -H "Authorization: Bearer ${NURSE_TOKEN}" \
  -H "Accept: application/fhir+json" \
  -H "X-Break-Glass: true" \
  -H "X-Break-Glass-Justification: Emergency cardiac event")

BG_HTTP_CODE=$(echo "$BREAKGLASS_RESPONSE" | tail -1)
BG_BODY=$(echo "$BREAKGLASS_RESPONSE" | sed '$d')

echo "  HTTP ${BG_HTTP_CODE}"
if [ "$BG_HTTP_CODE" = "200" ]; then
  echo "  Response (break-glass — expect ALL fields visible, no redaction):"
  echo "$BG_BODY" | python3 -m json.tool 2>/dev/null || echo "$BG_BODY"
else
  echo "  Response:"
  echo "$BG_BODY" | python3 -m json.tool 2>/dev/null || echo "$BG_BODY"
fi

echo ""
echo "=== Done ==="
