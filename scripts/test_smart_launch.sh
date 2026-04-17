#!/usr/bin/env bash
# Automate the SMART App Launch (authorization_code + PKCE) flow using
# curl, then call the FHIR proxy with the obtained token.
#
# This script simulates what the demo-app does in the browser:
#   1. Generate PKCE code_verifier + code_challenge (S256)
#   2. GET the Keycloak authorize endpoint (picks up session cookie)
#   3. POST credentials to the Keycloak login form
#   4. Extract the authorization code from the redirect
#   5. Exchange code for tokens with code_verifier
#   6. Call /fhir/r4/Patient through the proxy
#
# Prerequisites: make up (stack running)
#
# Usage: ./scripts/test_smart_launch.sh [username] [password]
#   KEYCLOAK_URL   (default http://localhost:8180)
#   PROXY_URL      (default http://localhost:8080)
#   REDIRECT_URI   (default http://localhost:3001/)

set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8180}"
REALM="${REALM:-hospital-a}"
CLIENT_ID="${CLIENT_ID:-fhir-privacy-proxy}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:3001/}"
PROXY_URL="${PROXY_URL:-http://localhost:8080}"
USERNAME="${1:-nurse1}"
PASSWORD="${2:-password}"

color() { printf "\033[1;%dm%s\033[0m\n" "$1" "$2"; }
title() { echo; color 34 "=== $* ==="; }
ok()    { color 32 "  ✓ $*"; }
fail()  { color 31 "  ✗ $*"; exit 1; }
dim()   { color 90 "    $*"; }

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
COOKIES="$TMPDIR/cookies"

# -----------------------------------------------------------
# Step 1 — Generate PKCE pair
# -----------------------------------------------------------
title "PKCE code challenge"

CODE_VERIFIER=$(openssl rand -base64 96 | tr -d '=+/\n' | head -c 128)
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 16)

ok "code_verifier  = ${CODE_VERIFIER:0:20}..."
ok "code_challenge = ${CODE_CHALLENGE:0:20}..."
ok "state          = ${STATE}"

# -----------------------------------------------------------
# Step 2 — Start authorize flow (get login page + session)
# -----------------------------------------------------------
title "Authorize endpoint"

AUTH_PARAMS=$(python3 -c "
import urllib.parse
print(urllib.parse.urlencode({
    'response_type': 'code',
    'client_id': '${CLIENT_ID}',
    'redirect_uri': '${REDIRECT_URI}',
    'scope': 'openid',
    'state': '${STATE}',
    'code_challenge': '${CODE_CHALLENGE}',
    'code_challenge_method': 'S256',
}))")

AUTH_URL="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/auth?${AUTH_PARAMS}"
dim "GET ${AUTH_URL:0:80}..."

LOGIN_PAGE=$(curl -s -c "$COOKIES" -L "$AUTH_URL")

ACTION_URL=$(echo "$LOGIN_PAGE" | grep -oP 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//' | python3 -c "import sys,html; print(html.unescape(sys.stdin.read().strip()))")

if [ -z "$ACTION_URL" ]; then
    fail "Could not find login form action URL in Keycloak response"
fi
ok "Got login form (action URL found)"

# -----------------------------------------------------------
# Step 3 — Submit credentials
# -----------------------------------------------------------
title "Submitting credentials for ${USERNAME}"

LOGIN_RESP=$(curl -s -b "$COOKIES" -c "$COOKIES" -D "$TMPDIR/headers" \
    -X POST "$ACTION_URL" \
    -d "username=${USERNAME}" \
    -d "password=${PASSWORD}" \
    --max-redirs 0 2>&1 || true)

LOCATION=$(grep -i '^location:' "$TMPDIR/headers" | head -1 | tr -d '\r' | sed 's/^[Ll]ocation: *//')

if [ -z "$LOCATION" ]; then
    fail "No redirect after login — check credentials (${USERNAME}/${PASSWORD})"
fi

CODE=$(echo "$LOCATION" | grep -oP 'code=[^&]*' | sed 's/code=//')
RETURNED_STATE=$(echo "$LOCATION" | grep -oP 'state=[^&]*' | sed 's/state=//')

if [ -z "$CODE" ]; then
    fail "No authorization code in redirect: ${LOCATION}"
fi

if [ "$RETURNED_STATE" != "$STATE" ]; then
    fail "State mismatch: expected ${STATE}, got ${RETURNED_STATE}"
fi

ok "Authorization code received (${CODE:0:20}...)"
ok "State verified"

# -----------------------------------------------------------
# Step 4 — Exchange code for tokens
# -----------------------------------------------------------
title "Token exchange"

TOKEN_RESPONSE=$(curl -s -X POST \
    "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code" \
    -d "client_id=${CLIENT_ID}" \
    -d "code=${CODE}" \
    -d "redirect_uri=${REDIRECT_URI}" \
    -d "code_verifier=${CODE_VERIFIER}")

TOKEN_ERROR=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || echo "parse_error")

if [ -n "$TOKEN_ERROR" ] && [ "$TOKEN_ERROR" != "" ]; then
    TOKEN_DESC=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error_description','unknown'))" 2>/dev/null || echo "")
    fail "Token exchange failed: ${TOKEN_ERROR} — ${TOKEN_DESC}"
fi

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$ACCESS_TOKEN" ]; then
    fail "Could not extract access_token"
fi

ok "Access token obtained"

# Decode and display claims
dim "Token claims:"
echo "$ACCESS_TOKEN" | python3 -c "
import sys, json, base64
token = sys.stdin.read().strip()
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload))
print('    sub:        ', claims.get('sub', '?'))
print('    preferred:  ', claims.get('preferred_username', '?'))
print('    roles:      ', claims.get('realm_access', {}).get('roles', []))
print('    fhir_role:  ', claims.get('fhirContext', {}).get('role', '?'))
print('    fhir_dept:  ', claims.get('fhirContext', {}).get('department', '?'))
print('    aud:        ', claims.get('aud', '?'))
print('    exp:        ', claims.get('exp', '?'))
"

# -----------------------------------------------------------
# Step 5 — Call FHIR proxy
# -----------------------------------------------------------
title "FHIR proxy call"

dim "GET ${PROXY_URL}/fhir/r4/Patient?_count=1"
FHIR_RESP=$(curl -s -w "\n%{http_code}" \
    "${PROXY_URL}/fhir/r4/Patient?_count=1" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Accept: application/fhir+json")

FHIR_CODE=$(echo "$FHIR_RESP" | tail -1)
FHIR_BODY=$(echo "$FHIR_RESP" | sed '$d')

if [ "$FHIR_CODE" = "200" ]; then
    ok "HTTP 200 — FHIR response received"
    echo "$FHIR_BODY" | python3 -c "
import sys, json
bundle = json.load(sys.stdin)
print('    resourceType:', bundle.get('resourceType'))
entries = bundle.get('entry', [])
print('    entries:     ', len(entries))
if entries:
    r = entries[0].get('resource', {})
    print('    first patient:', r.get('id', '?'))
    for f in ['identifier', 'telecom', 'address', 'birthDate']:
        if f not in r:
            print(f'    {f:14s}: REMOVED')
        elif r[f] == '***REDACTED***':
            print(f'    {f:14s}: MASKED')
        else:
            print(f'    {f:14s}: VISIBLE')
" 2>/dev/null
else
    fail "HTTP ${FHIR_CODE}: ${FHIR_BODY}"
fi

# -----------------------------------------------------------
# Step 6 — Also test metadata (unauthenticated)
# -----------------------------------------------------------
title "Metadata endpoint (no auth)"

META_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/fhir/r4/metadata")
if [ "$META_CODE" = "200" ]; then
    ok "GET /fhir/r4/metadata returned 200 (no auth required)"
else
    fail "GET /fhir/r4/metadata returned ${META_CODE}"
fi

title "All checks passed"
