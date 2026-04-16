#!/usr/bin/env bash
# Attack simulation — drives the AI risk engine with a mix of normal and
# suspicious traffic so you can see the Isolation Forest score move and
# the adaptive OPA policy reshape responses.
#
# Phases:
#   1. Baseline          — nurse hits /Patient during business hours
#   2. Bulk extraction   — 100 back-to-back GETs from one token
#   3. Sensitive snooping — repeated hits on a flagged patient
#   4. Out-of-hours      — direct /score with hour=3
#   5. Department mismatch — direct /score with mismatched dept
#   6. Break-glass abuse — break-glass on a non-emergency resource
#
# Requirements:
#   - `make up` brings the stack up (proxy, keycloak, opa, fhir, risk)
#   - RISK_SERVICE_URL is wired into the proxy (docker-compose.yml)
#
# Usage: ./scripts/attack_sim.sh
#   PROXY_URL     default http://localhost:8080
#   RISK_URL      default http://localhost:8000
#   FHIR_DIRECT   default http://localhost:8090/fhir
#   BULK_COUNT    default 100

set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8080}"
RISK_URL="${RISK_URL:-http://localhost:8000}"
FHIR_DIRECT="${FHIR_DIRECT:-http://localhost:8090/fhir}"
BULK_COUNT="${BULK_COUNT:-100}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

color() { printf "\033[1;%dm%s\033[0m\n" "$1" "$2"; }
title() { echo; color 34 "=== $* ==="; }
ok()    { color 32 "  ✓ $*"; }
warn()  { color 33 "  ! $*"; }
fail()  { color 31 "  ✗ $*"; }
dim()   { color 90 "    $*"; }

# -----------------------------------------------------------
# Preflight — make sure the stack is up
# -----------------------------------------------------------
title "Preflight"

if ! curl -s -f "${PROXY_URL}/health" > /dev/null; then
    fail "proxy not reachable at ${PROXY_URL} — did you run 'make up'?"
    exit 1
fi
ok "proxy up"

if ! curl -s -f "${RISK_URL}/health" > /dev/null; then
    warn "risk service not reachable at ${RISK_URL}"
    warn "phases 4-5 will be skipped"
    HAS_RISK=0
else
    ok "risk service up"
    HAS_RISK=1
fi

# -----------------------------------------------------------
# Helpers
# -----------------------------------------------------------
fetch_token() {
    local user="$1"
    "$SCRIPT_DIR/get_token.sh" "$user" password
}

# score_direct <label> <json-body> — hits FastAPI /score directly and
# pretty-prints the returned score + label.
score_direct() {
    local label="$1"
    local body="$2"
    local resp
    resp=$(curl -s -X POST "${RISK_URL}/score" \
        -H "Content-Type: application/json" \
        -d "$body")
    local score lab
    score=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('score','?'))")
    lab=$(echo   "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('label','?'))")
    local expl
    expl=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); e=d.get('explanation',{}); print(', '.join(f'{k}={v}' for k,v in e.items()) or '-')")
    dim "${label}: score=${score} label=${lab} drivers=[${expl}]"
}

# patient_request <token> <id> [extra-headers...] — hits the proxy,
# returns the HTTP code and the body fields we care about.
patient_request() {
    local token="$1"
    local pid="$2"
    shift 2
    curl -s -o /tmp/attack_body -w "%{http_code}" \
        "${PROXY_URL}/fhir/r4/Patient/${pid}" \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/fhir+json" \
        "$@"
}

# -----------------------------------------------------------
# Seed a baseline patient so there's something to target
# -----------------------------------------------------------
title "Seeding baseline + sensitive patients"

seed_patient() {
    local family="$1" mrn="$2"
    curl -s -X POST "${FHIR_DIRECT}/Patient" \
        -H "Content-Type: application/fhir+json" \
        -d "{
            \"resourceType\": \"Patient\",
            \"identifier\": [{\"system\":\"mrn\",\"value\":\"${mrn}\"}],
            \"name\":       [{\"family\":\"${family}\",\"given\":[\"Attack\"]}],
            \"telecom\":    [{\"system\":\"phone\",\"value\":\"555-1234\"}],
            \"address\":    [{\"city\":\"Springfield\"}],
            \"gender\":     \"other\",
            \"birthDate\":  \"1990-01-01\"
        }" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))"
}

BASE_ID=$(seed_patient "Baseline" "MRN-ATK-B1")
SENSITIVE_ID=$(seed_patient "VIP" "MRN-ATK-S1")
ok "baseline  = Patient/${BASE_ID}"
ok "sensitive = Patient/${SENSITIVE_ID} (add to policies/data.json sensitive_patients)"

NURSE_TOKEN=$(fetch_token nurse1)
DOCTOR_TOKEN=$(fetch_token doctor1)
ok "got nurse1 + doctor1 tokens"

# -----------------------------------------------------------
# Phase 1 — baseline
# -----------------------------------------------------------
title "Phase 1: baseline nurse → baseline patient"
code=$(patient_request "$NURSE_TOKEN" "$BASE_ID")
dim "HTTP ${code}"
[ "$code" = "200" ] && ok "allowed" || fail "unexpected HTTP $code"

# -----------------------------------------------------------
# Phase 2 — bulk extraction
# -----------------------------------------------------------
title "Phase 2: bulk extraction (${BULK_COUNT} reads back-to-back)"
dim "rate limiter is the first backstop; ML risk scoring is the second"
allowed=0 denied=0 rate_limited=0
start=$(date +%s)
for i in $(seq 1 "$BULK_COUNT"); do
    code=$(patient_request "$NURSE_TOKEN" "$BASE_ID")
    case "$code" in
        200) allowed=$((allowed+1)) ;;
        429) rate_limited=$((rate_limited+1)) ;;
        *)   denied=$((denied+1)) ;;
    esac
done
end=$(date +%s)
dim "elapsed: $((end-start))s  allowed=${allowed}  denied=${denied}  rate_limited=${rate_limited}"

# When REDIS_ADDR is set in docker-compose, the proxy enforces
# requests_per_minute per (tenant,subject). A burst of BULK_COUNT from
# one token should therefore start returning 429s once the minute budget
# for nurse1 is exhausted. If rate_limited==0 the limiter is disabled
# (Redis not wired) — flag it so the operator knows the AI layer is
# carrying the whole load.
if [ "$rate_limited" -gt 0 ]; then
    ok "rate limiter fired ${rate_limited}x — bulk extraction backstopped before reaching ML"
else
    warn "no 429s — rate limiter not active (REDIS_ADDR unset?). ML is the only backstop."
fi

dim "check /metrics → fhir_proxy_rate_limit_hits_total, fhir_proxy_policy_outcome_total, fhir_proxy_risk_scores_total"

# Pull the rate-limit counter directly so the operator sees the numeric
# evidence without needing to grep /metrics manually.
rl_metrics=$(curl -s "${PROXY_URL}/metrics" | grep '^fhir_proxy_rate_limit_hits_total' || true)
if [ -n "$rl_metrics" ]; then
    dim "rate-limit metrics snapshot:"
    echo "$rl_metrics" | sed 's/^/      /'
fi

# -----------------------------------------------------------
# Phase 3 — sensitive snooping
# -----------------------------------------------------------
title "Phase 3: sensitive snooping (nurse → VIP)"
code=$(patient_request "$NURSE_TOKEN" "$SENSITIVE_ID")
dim "HTTP ${code}"
if [ "$code" = "403" ]; then
    ok "denied as expected (VIP tagged, nurse has no break-glass)"
else
    warn "HTTP ${code} — ensure ${SENSITIVE_ID} is in policies/data.json sensitive_patients"
fi

dim "nurse + break-glass on VIP"
code=$(patient_request "$NURSE_TOKEN" "$SENSITIVE_ID" \
    -H "X-Break-Glass: true" \
    -H "X-Break-Glass-Justification: Attack-sim: simulated Code Blue")
dim "HTTP ${code}"
[ "$code" = "200" ] && ok "break-glass allowed (audited)" || warn "unexpected HTTP $code"

# -----------------------------------------------------------
# Phase 4-6 — direct calls to the risk service for scenarios that
# can't be spoofed through the proxy (hour comes from the proxy's clock).
# -----------------------------------------------------------
if [ "$HAS_RISK" -eq 1 ]; then
    title "Phase 4: out-of-hours access (direct /score)"
    score_direct "nurse @ 3am (normal dept)" "$(cat <<'JSON'
{"user_id":"nurse1","role":"nurse","department":"cardiology",
 "patient_id":"X","resource_type":"Patient","action":"read",
 "hour":3,"day_of_week":6,"break_glass":false,
 "patient_sensitive":false,"department_match":true}
JSON
    )"
    score_direct "nurse @ 9am (baseline control)" "$(cat <<'JSON'
{"user_id":"nurse1","role":"nurse","department":"cardiology",
 "patient_id":"X","resource_type":"Patient","action":"read",
 "hour":9,"day_of_week":2,"break_glass":false,
 "patient_sensitive":false,"department_match":true}
JSON
    )"

    title "Phase 5: department mismatch (direct /score)"
    score_direct "nurse crosses into oncology" "$(cat <<'JSON'
{"user_id":"nurse1","role":"nurse","department":"cardiology",
 "patient_id":"X","resource_type":"Patient","action":"read",
 "hour":14,"day_of_week":2,"break_glass":false,
 "patient_sensitive":false,"department_match":false}
JSON
    )"
    score_direct "nurse inside own dept (control)" "$(cat <<'JSON'
{"user_id":"nurse1","role":"nurse","department":"cardiology",
 "patient_id":"X","resource_type":"Patient","action":"read",
 "hour":14,"day_of_week":2,"break_glass":false,
 "patient_sensitive":false,"department_match":true}
JSON
    )"

    title "Phase 6: sensitive patient, no break-glass (direct /score)"
    score_direct "nurse snooping VIP quietly" "$(cat <<'JSON'
{"user_id":"nurse1","role":"nurse","department":"cardiology",
 "patient_id":"VIP","resource_type":"Patient","action":"read",
 "hour":23,"day_of_week":6,"break_glass":false,
 "patient_sensitive":true,"department_match":false}
JSON
    )"
    score_direct "same access but break-glass flagged" "$(cat <<'JSON'
{"user_id":"nurse1","role":"nurse","department":"cardiology",
 "patient_id":"VIP","resource_type":"Patient","action":"read",
 "hour":23,"day_of_week":6,"break_glass":true,
 "patient_sensitive":true,"department_match":false}
JSON
    )"
else
    warn "skipping phases 4-6 — risk service not reachable"
fi

# -----------------------------------------------------------
# Summary
# -----------------------------------------------------------
title "Done"
echo
echo "Next steps:"
echo "  1. curl ${PROXY_URL}/metrics | grep fhir_proxy_ — check policy + risk counters"
echo "  2. Inspect the audit trail (docker volume proxy-audit, /app/audit/audit.ndjson)"
echo "  3. Tune policies/data.json sensitive_patients to include ${SENSITIVE_ID}"
echo
echo "Expected score movement (phases 4-6):"
echo "  out-of-hours      → suspicious (>= 0.6)"
echo "  dept mismatch     → suspicious"
echo "  VIP + no BG + 11pm → anomalous (>= 0.85)"
echo "  VIP + BG          → still elevated but allowed, audited as break-glass"
