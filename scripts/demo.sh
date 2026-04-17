#!/usr/bin/env bash
# End-to-end demo: 3 users (nurse, doctor, admin) x 3 patients
# (normal, sensitive, emergency). Walks through masking, removal, and
# break-glass behaviour via the proxy so you can see the full policy
# engine at work.
#
# Prereqs: `make up` is running.
#
# Usage: ./scripts/demo.sh
#   FHIR_DIRECT  (default http://localhost:8090/fhir)
#   PROXY_URL    (default http://localhost:8080)

set -euo pipefail

FHIR_DIRECT="${FHIR_DIRECT:-http://localhost:8090/fhir}"
PROXY_URL="${PROXY_URL:-http://localhost:8080}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

color() { printf "\033[1;%dm%s\033[0m\n" "$1" "$2"; }
title() { echo; color 34 "=== $* ==="; }
ok()    { color 32 "  ✓ $*"; }
warn()  { color 33 "  ! $*"; }
fail()  { color 31 "  ✗ $*"; }
dim()   { color 90 "    $*"; }

# -----------------------------------------------------------
# Step 1 — seed three patients
# -----------------------------------------------------------
title "Seeding 3 patients on the upstream FHIR server"

seed_patient() {
    local label="$1"
    local mrn="$2"
    curl -s -X POST "${FHIR_DIRECT}/Patient" \
        -H "Content-Type: application/fhir+json" \
        -d "{
            \"resourceType\": \"Patient\",
            \"identifier\": [{\"system\": \"mrn\", \"value\": \"${mrn}\"}],
            \"name\":       [{\"family\": \"${label}\", \"given\": [\"Demo\"]}],
            \"telecom\":    [{\"system\": \"phone\", \"value\": \"555-0000\"}],
            \"address\":    [{\"city\": \"Springfield\"}],
            \"gender\":     \"other\",
            \"birthDate\":  \"1990-01-01\"
        }" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))"
}

NORMAL_ID=$(seed_patient "Normal" "MRN-N001")
SENSITIVE_ID=$(seed_patient "Sensitive" "MRN-S001")
EMERGENCY_ID=$(seed_patient "Emergency" "MRN-E001")

ok "normal   = Patient/${NORMAL_ID}"
ok "sensitive = Patient/${SENSITIVE_ID} (mark this id in policies/data.json)"
ok "emergency = Patient/${EMERGENCY_ID}"

# -----------------------------------------------------------
# Step 2 — get tokens
# -----------------------------------------------------------
title "Fetching tokens"
NURSE_TOKEN=$("$SCRIPT_DIR/get_token.sh" nurse1 password)
DOCTOR_TOKEN=$("$SCRIPT_DIR/get_token.sh" doctor1 password)
ADMIN_TOKEN=$("$SCRIPT_DIR/get_token.sh" admin1 password)
ok "got tokens for nurse1 / doctor1 / admin1"

# -----------------------------------------------------------
# helpers
# -----------------------------------------------------------
query() {
    local label="$1"
    local token="$2"
    local pid="$3"
    shift 3
    local code body
    response=$(curl -s -w "\n%{http_code}" \
        "${PROXY_URL}/fhir/r4/Patient/${pid}" \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/fhir+json" \
        "$@")
    code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')
    dim "HTTP ${code}"
    if [ "$code" = "200" ]; then
        # Print which sensitive fields were redacted / masked
        identifier=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print('REMOVED' if 'identifier' not in d else ('MASKED' if d['identifier']=='***REDACTED***' else 'VISIBLE'))" 2>/dev/null || echo "?")
        telecom=$(echo   "$body" | python3 -c   "import sys,json; d=json.load(sys.stdin); print('MASKED'  if d.get('telecom')  =='***REDACTED***' else ('REMOVED' if 'telecom'  not in d else 'VISIBLE'))" 2>/dev/null || echo "?")
        address=$(echo   "$body" | python3 -c   "import sys,json; d=json.load(sys.stdin); print('MASKED'  if d.get('address')  =='***REDACTED***' else ('REMOVED' if 'address'  not in d else 'VISIBLE'))" 2>/dev/null || echo "?")
        ok   "identifier=${identifier}  telecom=${telecom}  address=${address}"
    else
        reason=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error_description',d.get('error','')))" 2>/dev/null || echo "$body")
        fail "denied: ${reason}"
    fi
}

# -----------------------------------------------------------
# Step 3 — normal patient access
# -----------------------------------------------------------
title "Normal patient — role-based redaction"

dim "nurse1  → Patient/${NORMAL_ID}"
query "nurse" "$NURSE_TOKEN" "$NORMAL_ID"

dim "doctor1 → Patient/${NORMAL_ID}"
query "doctor" "$DOCTOR_TOKEN" "$NORMAL_ID"

dim "admin1  → Patient/${NORMAL_ID}"
query "admin" "$ADMIN_TOKEN" "$NORMAL_ID"

# -----------------------------------------------------------
# Step 4 — sensitive patient
# -----------------------------------------------------------
title "Sensitive patient — nurse should be blocked"
warn "Add '${SENSITIVE_ID}' to policies/data.json sensitive_patients for this section to matter."

dim "nurse1  → Patient/${SENSITIVE_ID}"
query "nurse"  "$NURSE_TOKEN"  "$SENSITIVE_ID"

dim "doctor1 → Patient/${SENSITIVE_ID}"
query "doctor" "$DOCTOR_TOKEN" "$SENSITIVE_ID"

dim "admin1  → Patient/${SENSITIVE_ID}"
query "admin"  "$ADMIN_TOKEN"  "$SENSITIVE_ID"

# -----------------------------------------------------------
# Step 5 — emergency / break-glass
# -----------------------------------------------------------
title "Emergency patient — nurse break-glass"

dim "nurse1 (no break-glass) → Patient/${EMERGENCY_ID}"
query "nurse" "$NURSE_TOKEN" "$EMERGENCY_ID"

dim "nurse1 (break-glass=true) → Patient/${EMERGENCY_ID}"
query "nurse-bg" "$NURSE_TOKEN" "$EMERGENCY_ID" \
    -H "X-Break-Glass: true" \
    -H "X-Break-Glass-Justification: Code Blue cardiac arrest"

# -----------------------------------------------------------
# Step 6 — consent enforcement
# -----------------------------------------------------------
title "Consent enforcement"

# Seed two patients with different consent profiles.
dim "Seeding consent test patients..."
CONSENT_PID=$(seed_patient "ConsOK" "MRN-C001")
NOCONSENT_PID=$(seed_patient "ConsDenied" "MRN-C002")
ok "consent patient = Patient/${CONSENT_PID}"
ok "no-consent patient = Patient/${NOCONSENT_PID}"

# Post Consent resources via the upstream FHIR server.
dim "Posting Consent resources..."
curl -s -X POST "${FHIR_DIRECT}/Consent" \
    -H "Content-Type: application/fhir+json" \
    -d "{
        \"resourceType\": \"Consent\", \"status\": \"active\",
        \"scope\": {\"coding\": [{\"code\": \"patient-privacy\"}]},
        \"category\": [{\"coding\": [{\"code\": \"59284-0\"}]}],
        \"patient\": {\"reference\": \"Patient/${CONSENT_PID}\"},
        \"provision\": {\"type\": \"permit\", \"purpose\": [{\"code\": \"TREATMENT\"}, {\"code\": \"PAYMENT\"}]}
    }" > /dev/null
ok "Consent for Patient/${CONSENT_PID}: TREATMENT + PAYMENT"

curl -s -X POST "${FHIR_DIRECT}/Consent" \
    -H "Content-Type: application/fhir+json" \
    -d "{
        \"resourceType\": \"Consent\", \"status\": \"active\",
        \"scope\": {\"coding\": [{\"code\": \"patient-privacy\"}]},
        \"category\": [{\"coding\": [{\"code\": \"59284-0\"}]}],
        \"patient\": {\"reference\": \"Patient/${NOCONSENT_PID}\"},
        \"provision\": {\"type\": \"permit\", \"purpose\": [{\"code\": \"RESEARCH\"}]}
    }" > /dev/null
ok "Consent for Patient/${NOCONSENT_PID}: RESEARCH only"

dim "doctor1 + TREATMENT → Patient/${CONSENT_PID} (should ALLOW)"
query "doctor-consent" "$DOCTOR_TOKEN" "$CONSENT_PID" \
    -H "X-Purpose-Of-Use: TREATMENT"

dim "doctor1 + TREATMENT → Patient/${NOCONSENT_PID} (should DENY — only RESEARCH)"
query "doctor-noconsent" "$DOCTOR_TOKEN" "$NOCONSENT_PID" \
    -H "X-Purpose-Of-Use: TREATMENT"

dim "doctor1 + EMERGENCY → Patient/${NOCONSENT_PID} (should ALLOW — EMERGENCY bypasses consent)"
query "doctor-emergency" "$DOCTOR_TOKEN" "$NOCONSENT_PID" \
    -H "X-Purpose-Of-Use: EMERGENCY"

title "Done"
echo
echo "Expected outcomes summary:"
echo "  nurse (normal)        -> identifier REMOVED, telecom+address MASKED"
echo "  doctor (normal)       -> identifier VISIBLE, address MASKED"
echo "  admin (normal)        -> all fields VISIBLE"
echo "  nurse (sensitive)     -> 403 (unless break-glass)"
echo "  nurse (break-glass)   -> all fields VISIBLE, audited as BREAK_GLASS"
echo "  doctor + TREATMENT    -> consented patient OK, non-consented DENIED"
echo "  doctor + EMERGENCY    -> non-consented patient ALLOWED (emergency bypass)"
