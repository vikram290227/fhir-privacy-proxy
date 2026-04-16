#!/usr/bin/env bash
#
# admin.sh — thin curl wrapper around the FHIR proxy management API
# (/admin/v1, gated by X-Admin-Key).
#
# All endpoints require ADMIN_API_KEY in the environment to match what
# the proxy was started with. PROXY_URL defaults to http://localhost:8080
# but can be overridden so this works against staging just as well.
#
# Examples:
#
#   ADMIN_API_KEY=secret ./scripts/admin.sh versions
#   ADMIN_API_KEY=secret ./scripts/admin.sh activate v3
#   ADMIN_API_KEY=secret ./scripts/admin.sh rollback
#   ADMIN_API_KEY=secret ./scripts/admin.sh tenants
#   ADMIN_API_KEY=secret ./scripts/admin.sh audit-tail 100
#   ADMIN_API_KEY=secret ./scripts/admin.sh revoke hospital-a abc-123 1735689600
#   ADMIN_API_KEY=secret ./scripts/admin.sh health

set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8080}"
ADMIN_API_KEY="${ADMIN_API_KEY:-}"

if [ -z "$ADMIN_API_KEY" ]; then
  echo "ERROR: ADMIN_API_KEY env var is required (must match what the proxy was started with)" >&2
  exit 1
fi

# Pretty-print JSON if jq is available, otherwise raw passthrough so
# the script still works in stripped-down containers.
pp() {
  if command -v jq >/dev/null 2>&1; then
    jq .
  else
    cat
  fi
}

req() {
  local method="$1"; shift
  local path="$1"; shift
  curl -sS -X "$method" \
    -H "X-Admin-Key: ${ADMIN_API_KEY}" \
    -H "Content-Type: application/json" \
    "${PROXY_URL}/admin/v1${path}" \
    "$@"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [args]

Commands:
  versions                       List policy bundles + active version
  activate <version>             Switch active policy bundle (uploads to OPA)
  rollback                       Pop one history entry (uploads previous bundle)
  tenants                        List configured tenants (sensitive lists redacted)
  audit-tail [n]                 Tail the last n audit lines (default 50)
  revoke <tenant> <jti> <exp>    Revoke a JWT by jti (exp is unix seconds)
  health                         Status of OPA / Redis / FHIR upstream / risk service

Env:
  ADMIN_API_KEY  required, must match the value the proxy was started with
  PROXY_URL      default: http://localhost:8080
EOF
}

cmd="${1:-}"
case "$cmd" in
  versions)
    req GET /policy/versions | pp
    ;;
  activate)
    if [ $# -lt 2 ]; then echo "activate <version>" >&2; exit 2; fi
    req POST /policy/activate -d "{\"version\":\"$2\"}" | pp
    ;;
  rollback)
    req POST /policy/rollback | pp
    ;;
  tenants)
    req GET /tenants | pp
    ;;
  audit-tail)
    n="${2:-50}"
    req GET "/audit/tail?n=${n}" | pp
    ;;
  revoke)
    if [ $# -lt 4 ]; then
      echo "revoke <tenant> <jti> <exp>" >&2
      exit 2
    fi
    req POST /tokens/revoke -d "{\"tenant\":\"$2\",\"jti\":\"$3\",\"exp\":$4}" | pp
    ;;
  health)
    req GET /health/deps | pp
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    echo "unknown command: $cmd" >&2
    usage
    exit 2
    ;;
esac
