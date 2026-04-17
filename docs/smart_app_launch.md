# SMART App Launch (Authorization Code + PKCE)

The proxy supports the [SMART App Launch Framework](http://hl7.org/fhir/smart-app-launch/)
using the authorization code grant with PKCE (Proof Key for Code Exchange).
This is the standard flow for browser-based SMART-on-FHIR applications.

## Sequence Diagram

```
 Browser (Demo App)          Keycloak (IdP)              Proxy (8080)         Upstream FHIR
       │                          │                          │                      │
       │  1. User clicks Launch   │                          │                      │
       │─────────────────────────>│                          │                      │
       │  GET /auth?              │                          │                      │
       │    response_type=code    │                          │                      │
       │    client_id=...         │                          │                      │
       │    redirect_uri=...      │                          │                      │
       │    code_challenge=...    │                          │                      │
       │    code_challenge_method │                          │                      │
       │    =S256                 │                          │                      │
       │    scope=openid          │                          │                      │
       │    state=<random>        │                          │                      │
       │                          │                          │                      │
       │  2. Login page           │                          │                      │
       │<─────────────────────────│                          │                      │
       │                          │                          │                      │
       │  3. POST credentials     │                          │                      │
       │─────────────────────────>│                          │                      │
       │                          │                          │                      │
       │  4. 302 redirect with    │                          │                      │
       │     ?code=...&state=...  │                          │                      │
       │<─────────────────────────│                          │                      │
       │                          │                          │                      │
       │  5. Verify state match   │                          │                      │
       │  6. POST /token          │                          │                      │
       │    grant_type=           │                          │                      │
       │      authorization_code  │                          │                      │
       │    code=<auth_code>      │                          │                      │
       │    code_verifier=<pkce>  │                          │                      │
       │    redirect_uri=...      │                          │                      │
       │─────────────────────────>│                          │                      │
       │                          │                          │                      │
       │  7. { access_token,      │                          │                      │
       │       id_token,          │                          │                      │
       │       refresh_token }    │                          │                      │
       │<─────────────────────────│                          │                      │
       │                          │                          │                      │
       │  8. GET /fhir/r4/Patient/123                        │                      │
       │     Authorization: Bearer <access_token>            │                      │
       │────────────────────────────────────────────────────>│                      │
       │                          │                          │                      │
       │                          │  9. Validate JWT (sig,   │                      │
       │                          │     aud, iss via JWKS)   │                      │
       │                          │  10. Enforce SMART scope │                      │
       │                          │  11. Rate limit          │                      │
       │                          │  12. Score risk (ML)     │                      │
       │                          │  13. Check consent       │                      │
       │                          │  14. OPA policy eval     │                      │
       │                          │                          │                      │
       │                          │                          │  15. GET /Patient/123 │
       │                          │                          │─────────────────────>│
       │                          │                          │  16. Full resource    │
       │                          │                          │<─────────────────────│
       │                          │                          │                      │
       │                          │  17. Apply redactions    │                      │
       │                          │      (remove/mask per    │                      │
       │                          │       OPA decision)      │                      │
       │                          │                          │                      │
       │  18. Redacted Patient resource                      │                      │
       │<────────────────────────────────────────────────────│                      │
```

## PKCE (Proof Key for Code Exchange)

PKCE prevents authorization code interception attacks. The flow:

1. **App generates** a random `code_verifier` (43-128 chars, URL-safe)
2. **App derives** `code_challenge = BASE64URL(SHA256(code_verifier))`
3. **Authorize request** includes `code_challenge` + `code_challenge_method=S256`
4. **Token exchange** includes `code_verifier` (Keycloak verifies the hash matches)

The Keycloak client enforces S256 via `pkce.code.challenge.method` — requests
without a valid code challenge are rejected.

## Keycloak Configuration

Both realm clients (`fhir-privacy-proxy` for hospital-a, `fhir-privacy-proxy-b`
for hospital-b) are configured with:

| Setting | Value |
|---------|-------|
| `publicClient` | `true` (no client secret) |
| `standardFlowEnabled` | `true` (authorization code grant) |
| `directAccessGrantsEnabled` | `true` (password grant for scripts) |
| `pkce.code.challenge.method` | `S256` |
| `redirectUris` | `http://localhost:3001/*` |
| `webOrigins` | `http://localhost:3001` (CORS) |

## Endpoints

| Endpoint | URL |
|----------|-----|
| Authorize | `http://localhost:8180/realms/hospital-a/protocol/openid-connect/auth` |
| Token | `http://localhost:8180/realms/hospital-a/protocol/openid-connect/token` |
| JWKS | `http://localhost:8180/realms/hospital-a/protocol/openid-connect/certs` |
| FHIR base | `http://localhost:8080/fhir/r4` |
| Metadata | `http://localhost:8080/fhir/r4/metadata` (unauthenticated) |

## Demo App

A minimal browser-based SMART app lives in `demo-app/index.html`. It runs on
port 3001 via the `demo-app` Docker Compose service.

```bash
make up
open http://localhost:3001
```

The app:
1. Lets you pick a user (nurse1, doctor1, admin1)
2. Redirects to Keycloak for login (authorization code + PKCE)
3. Exchanges the code for tokens
4. Calls `/fhir/r4/Patient` through the proxy
5. Displays the response with a field-by-field redaction analysis

### What to observe

| User | identifier | telecom | address | birthDate |
|------|-----------|---------|---------|-----------|
| nurse1 | REMOVED | MASKED | MASKED | visible |
| doctor1 | visible | visible | MASKED | visible |
| admin1 | visible | visible | visible | visible |

## Automated Test

`scripts/test_smart_launch.sh` automates the full flow using curl:

```bash
./scripts/test_smart_launch.sh nurse1 password
./scripts/test_smart_launch.sh doctor1 password
./scripts/test_smart_launch.sh admin1 password
```

It generates PKCE, submits credentials to Keycloak's login form, extracts the
authorization code, exchanges it for a token, and calls the FHIR proxy —
verifying each step along the way.

## Security Notes

- The demo app is a **public client** (no client secret). In production,
  confidential clients with a backend should be used for server-side apps.
- PKCE is mandatory (S256). Plain code challenges are rejected.
- The `state` parameter prevents CSRF attacks on the redirect.
- Tokens are stored in `sessionStorage` (cleared on tab close, not
  accessible to other tabs).
- The proxy validates every token independently — it never trusts the
  demo app's claim about the user's identity.
