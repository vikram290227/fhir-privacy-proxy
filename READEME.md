# FHIR Privacy Proxy - MVP

Working SMART-on-FHIR authentication and authorization proxy.

## What This MVP Includes

✅ JWT validation with JWKS (auto-refresh)
✅ Multi-tenant support (issuer-based routing)
✅ OPA policy enforcement (external container)
✅ Break-glass emergency access
✅ FHIR context claims (department, role, facility)
✅ Structured audit logging

## What's NOT in MVP (Future)

❌ Redis token revocation cache
❌ Embedded OPA (using HTTP instead)
❌ FHIR server proxy/filtering
❌ Keycloak event webhooks

## Quick Start

```bash
# 1. Start services
docker-compose up -d

# 2. Wait for Keycloak to start (about 30 seconds)
# Check: http://localhost:8180

# 3. Configure Keycloak
# - Create realm: hospital-a
# - Create client: fhir-privacy-proxy
# - Create user with roles: nurse, can_break_glass
# - Add user attribute: department = ED
# - Create protocol mapper for fhirContext claim

# 4. Test the proxy
curl http://localhost:8080/health
# Should return: OK

# 5. Get token from Keycloak and test
# (See docs/testing.md for full curl examples)
```

## Architecture

```
Client → [JWT] → Proxy → OPA → Decision
                   ↓
              Keycloak (JWKS)
```

## Testing Without Keycloak

Use this JWT (expired, for structure reference):
```
eyJhbGc...
```

## Next Steps

1. Set up Keycloak realm and protocol mappers
2. Create test users with fhirContext claims
3. Test break-glass with X-Break-Glass header
4. Add FHIR server proxy logic
5. Implement field-level filtering

## License

MIT