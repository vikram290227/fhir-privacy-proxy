# FHIR Privacy Proxy

SMART-on-FHIR authentication and authorization proxy with field-level redaction.

## Features

- JWT validation with JWKS (auto-refresh, per-tenant caching)
- Multi-tenant support (issuer-based routing)
- OPA policy enforcement (external container via HTTP)
- Break-glass emergency access override with audit logging
- FHIR context claims (department, role, facility)
- Field-level redaction (remove/mask) based on OPA policy decisions
- Bundle-aware redaction (redacts each entry individually)
- Redis token revocation cache with Keycloak webhook integration
- Per-tenant sliding-window rate limiting (minute + hour tiers) backed by Redis
- Scope validation against tenant-allowed scopes
- Prometheus metrics endpoint (`/metrics`)
- OpenTelemetry distributed tracing
- Structured audit logging (zap)
- Docker Compose orchestration with all dependencies

## Architecture

```
Client → [JWT] → Proxy (8080) → Upstream FHIR (8090)
                    │
                    ├─ Keycloak (8180) [JWKS validation]
                    ├─ OPA (8181)      [Policy decisions]
                    └─ Redis (6379)    [Token revocation]
```

**Request flow:**
1. `ValidateToken` — verifies JWT signature, audience, issuer via tenant JWKS
2. Revocation check — optionally checks Redis for revoked tokens
3. Scope validation — ensures token scopes match tenant-allowed scopes
4. `RequireSmartScope` — maps HTTP method + resource to SMART scope and enforces it
5. `RateLimit` — sliding-window rate limit per (tenant_id, subject_id), Redis-backed
6. `ScoreRisk` — calls ML service for anomaly score (skipped on 429)
7. `EnforcePolicy` — calls OPA for allow/deny + redaction rules
8. `fhirProxyHandler` — forwards to upstream, applies field-level redaction

## Quick Start

```bash
# Start all services
make up

# Wait for Keycloak (~30s), then test health
curl http://localhost:8080/health

# Get a token and test
./scripts/get_token.sh nurse1 password
./scripts/test_patient.sh
```

## Endpoints

| Endpoint | Description |
|---|---|
| `GET /health` | Health check |
| `GET /metrics` | Prometheus metrics |
| `POST /webhook/revoke` | Keycloak token revocation webhook |
| `GET /fhir/r4/*` | Protected FHIR proxy (requires JWT) |

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `TENANTS_CONFIG` | `configs/tenants.yaml` | Path to tenant registry |
| `OPA_URL` | `http://opa:8181` | OPA server URL |
| `FHIR_UPSTREAM` | `http://localhost:8090/fhir` | Upstream FHIR server |
| `REDIS_ADDR` | (disabled) | Redis address for token revocation **and** rate limiting |
| `RISK_SERVICE_URL` | (disabled) | FastAPI risk-scoring service URL |

### Rate limiting

A sliding-window rate limiter runs between `RequireSmartScope` and
`ScoreRisk` when `REDIS_ADDR` is set and the Redis at that address is
reachable at boot. It is the first backstop against bulk-extraction
abuse — the ML risk scoring layer catches novel patterns but cannot
tell apart "legitimate high-throughput EMR" from "script dumping every
Patient". The limiter is what stops that kind of volumetric attack
before it reaches OPA or the upstream FHIR server.

Limits are per **(tenant_id, subject_id)** and come from
`configs/tenants.yaml`:

```yaml
tenants:
  - tenant_id: hospital-a
    # ...
    requests_per_minute: 60    # short-burst tier
    requests_per_hour:  1000   # slow-and-low tier
```

Both tiers are enforced independently — exceeding *either* returns
**HTTP 429**. Omitting a field or setting it to `0` falls back to the
package defaults (60/min, 1000/hr). A limit of `0` explicitly disables
just that tier.

On a rejection the proxy emits:

- `Retry-After: <seconds>`
- `X-RateLimit-Limit-Minute`, `X-RateLimit-Limit-Hour`
- `X-RateLimit-Remaining-Minute`, `X-RateLimit-Remaining-Hour`
- `X-RateLimit-Reset-Minute`, `X-RateLimit-Reset-Hour` (unix seconds)

and increments the Prometheus counter
`fhir_proxy_rate_limit_hits_total{tenant,subject,window}` where
`window` is `"minute"` or `"hour"`.

If Redis is unreachable at runtime the limiter **fails open** (logs a
warning and lets the request through) — rate limiting is a defensive
backstop, not a correctness gate, so an infrastructure outage should
not break the proxy. Downstream OPA + ML still run.

`scripts/attack_sim.sh` Phase 2 fires `BULK_COUNT` (default 100) reads
from a single token and reports how many were rate-limited vs. denied
vs. allowed, plus a snapshot of the counter — a quick way to visually
confirm the backstop is doing its job.

## Test Users (Keycloak)

| User | Password | Roles | Department |
|---|---|---|---|
| `nurse1` | `password` | nurse, can_break_glass | cardiology |
| `doctor1` | `password` | doctor | cardiology |
| `admin1` | `password` | admin, doctor, can_break_glass | administration |

## Development

```bash
make build       # Compile binary
make test        # Run all tests
make test-cover  # Run tests with coverage report
make fmt         # Format code
make lint        # Run go vet
```

## License

MIT
