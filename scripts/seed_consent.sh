#!/usr/bin/env bash
# Seed FHIR Consent resources on the upstream HAPI FHIR server so the
# consent enforcement pipeline has something to evaluate.
#
# Usage: ./scripts/seed_consent.sh [patient_id_1] [patient_id_2]
#   FHIR_DIRECT  (default http://localhost:8090/fhir)
#
# When run without arguments the script creates two test patients and
# posts one Consent per patient:
#   * patient-consent  — active consent permitting TREATMENT + PAYMENT
#   * patient-noconsent — active consent permitting only RESEARCH
#
# Pass explicit IDs to attach consent to existing patients.

set -euo pipefail

FHIR_DIRECT="${FHIR_DIRECT:-http://localhost:8090/fhir}"

color() { printf "\033[1;%dm%s\033[0m\n" "$1" "$2"; }
ok()    { color 32 "  ✓ $*"; }
title() { echo; color 34 "=== $* ==="; }

# Create a patient if no IDs given.
create_patient() {
    local name="$1"
    curl -s -X POST "${FHIR_DIRECT}/Patient" \
        -H "Content-Type: application/fhir+json" \
        -d "{
            \"resourceType\": \"Patient\",
            \"identifier\": [{\"system\": \"mrn\", \"value\": \"MRN-${name}\"}],
            \"name\": [{\"family\": \"${name}\", \"given\": [\"Test\"]}],
            \"telecom\": [{\"system\": \"phone\", \"value\": \"555-1234\"}],
            \"address\": [{\"city\": \"Springfield\"}],
            \"gender\": \"other\",
            \"birthDate\": \"1985-06-15\"
        }" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))"
}

post_consent() {
    local patient_id="$1"
    local status="$2"
    local provision_type="$3"
    shift 3
    # remaining args are purpose codes
    local purposes=""
    for p in "$@"; do
        purposes="${purposes}{\"code\": \"${p}\"},"
    done
    purposes="${purposes%,}"

    curl -s -X POST "${FHIR_DIRECT}/Consent" \
        -H "Content-Type: application/fhir+json" \
        -d "{
            \"resourceType\": \"Consent\",
            \"status\": \"${status}\",
            \"scope\": {
                \"coding\": [{
                    \"system\": \"http://terminology.hl7.org/CodeSystem/consentscope\",
                    \"code\": \"patient-privacy\"
                }]
            },
            \"category\": [{
                \"coding\": [{
                    \"system\": \"http://loinc.org\",
                    \"code\": \"59284-0\"
                }]
            }],
            \"patient\": {
                \"reference\": \"Patient/${patient_id}\"
            },
            \"provision\": {
                \"type\": \"${provision_type}\",
                \"purpose\": [${purposes}]
            }
        }" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))"
}

title "Seeding Consent resources"

if [ $# -ge 2 ]; then
    PID_CONSENT="$1"
    PID_NOCONSENT="$2"
    ok "Using provided patient IDs"
else
    PID_CONSENT=$(create_patient "ConsentOK")
    PID_NOCONSENT=$(create_patient "ConsentDenied")
    ok "Created Patient/${PID_CONSENT} (will consent to TREATMENT+PAYMENT)"
    ok "Created Patient/${PID_NOCONSENT} (will consent to RESEARCH only)"
fi

CID1=$(post_consent "$PID_CONSENT" "active" "permit" "TREATMENT" "PAYMENT")
ok "Consent/${CID1} for Patient/${PID_CONSENT}: active, permit TREATMENT+PAYMENT"

CID2=$(post_consent "$PID_NOCONSENT" "active" "permit" "RESEARCH")
ok "Consent/${CID2} for Patient/${PID_NOCONSENT}: active, permit RESEARCH only"

title "Done"
echo "  PID_CONSENT=${PID_CONSENT}"
echo "  PID_NOCONSENT=${PID_NOCONSENT}"
echo
echo "Use these IDs with demo.sh or manually:"
echo "  curl -H 'Authorization: Bearer <token>' \\"
echo "       -H 'X-Purpose-Of-Use: TREATMENT' \\"
echo "       http://localhost:8080/fhir/r4/Patient/${PID_CONSENT}"
