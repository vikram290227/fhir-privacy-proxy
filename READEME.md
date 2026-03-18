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
4. `EnforcePolicy` — calls OPA for allow/deny + redaction rules
5. `fhirProxyHandler` — forwards to upstream, applies field-level redaction

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
| `REDIS_ADDR` | (disabled) | Redis address for token revocation |

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
