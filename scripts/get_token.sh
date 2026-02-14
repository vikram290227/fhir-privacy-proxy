#!/usr/bin/env bash
# Fetch an access token from Keycloak using the password grant.
# Usage: ./scripts/get_token.sh [username] [password]
#
# Defaults: nurse1 / password
# For local testing ONLY — password grant is disabled in production.

set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8180}"
REALM="${REALM:-hospital-a}"
CLIENT_ID="${CLIENT_ID:-fhir-privacy-proxy}"
USERNAME="${1:-nurse1}"
PASSWORD="${2:-password}"

TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"

RESPONSE=$(curl -s -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}" \
  -d "scope=openid")

# Check for error
if echo "$RESPONSE" | grep -q '"error"'; then
  echo "ERROR: Failed to get token" >&2
  echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE" >&2
  exit 1
fi

# Extract and print the access token
ACCESS_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$ACCESS_TOKEN" ]; then
  echo "ERROR: Could not extract access_token from response" >&2
  echo "$RESPONSE" >&2
  exit 1
fi

echo "$ACCESS_TOKEN"
