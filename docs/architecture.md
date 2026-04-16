# Architecture — FHIR Privacy Proxy + AI Risk Scoring

## System diagram

```
                                      ┌──────────────┐
                                      │   Keycloak   │
                                      │  (hospital-a)│
                                      └──────┬───────┘
                                             │ JWKS / OIDC
                                             ▼
┌──────────┐     Bearer JWT   ┌───────────────────────────────┐
│  Client  │ ────────────────▶│         FHIR Proxy (Go)       │
│  (EMR)   │◀──────────────── │                               │
└──────────┘    redacted FHIR │  ┌─────────────────────────┐  │
                              │  │  ValidateToken          │  │   (JWT + JWKS cache)
                              │  ├─────────────────────────┤  │
                              │  │  RequireSmartScope      │  │   (SMART v1/v2)
                              │  ├─────────────────────────┤  │
                              │  │  ScoreRisk ────────────▶│──┼──▶ ┌──────────────┐
                              │  │                         │  │    │ FastAPI ML   │
                              │  │                         │◀─┼─── │ risk_service │
                              │  ├─────────────────────────┤  │    │  iforest +   │
                              │  │  EnforcePolicy ────────▶│──┼──▶ │  SHAP        │
                              │  │                         │  │    └──────────────┘
                              │  │                         │◀─┼── ┌──────────────┐
                              │  ├─────────────────────────┤  │    │  OPA         │
                              │  │  fhirProxyHandler       │──┼──▶ │  authz.rego  │
                              │  │  (redaction)            │◀─┼─── │              │
                              │  └─────────────────────────┘  │    └──────────────┘
                              │                               │
                              │  ┌──────────┐   ┌──────────┐  │
                              │  │  audit   │   │ metrics  │  │
                              │  │ NDJSON   │   │ Prometheus│ │
                              │  └──────────┘   └──────────┘  │
                              └──────────────┬────────────────┘
                                             │
                                             ▼
                                   ┌──────────────────┐
                                   │ HAPI FHIR server │
                                   │     (upstream)   │
                                   └──────────────────┘
```

## Component responsibilities

### Go proxy (`cmd/proxy`)
Owns the request pipeline. Middleware chain, in order:

1. **ValidateToken** — parses the JWT, verifies signature via cached JWKS,
   loads tenant configuration, and builds the `SubjectContext`.
2. **RequireSmartScope** — maps the request's HTTP method + FHIR resource
   type to a required SMART scope (`patient/Patient.read`, etc.) and
   rejects requests whose token doesn't grant it.
3. **RateLimit** — Redis-backed sliding-window limiter keyed by
   `(tenant_id, subject_id)` with independent minute/hour tiers.
   Returns 429 with `Retry-After` + `X-RateLimit-*` headers on breach.
   No-op when `REDIS_ADDR` is unset. Runs before `ScoreRisk` so
   rejected requests never incur the ML round-trip.
4. **ScoreRisk** — calls the Python FastAPI service, attaches the
   returned score, label, and SHAP-style explanation to the subject
   context. Falls back to score=0 if the service is unreachable.
5. **EnforcePolicy** — POSTs the full subject + request + resource
   context to OPA, receives an allow/deny + remove/mask lists, and
   records the decision in Prometheus.
6. **fhirProxyHandler** — forwards the request to the upstream FHIR
   server, reads the JSON response, applies redactions (single
   resources and Bundles including nested bundles), then writes the
   response. An audit event is asynchronously appended to NDJSON.

### OPA (`policies/base/authz.rego`)
Rule engine. Reads `input.subject`, `input.request`, `input.resource`,
`input.subject.risk.score` and returns `allow`, `remove`, `mask`,
`reason`, `risk_score`. Thresholds:

- `risk_mask_threshold = 0.6`  → widen mask list
- `risk_deny_threshold = 0.85` → deny unless break-glass

### Versioned policies & rollback

Every policy bundle lives under `policies/versions/<version>/authz.rego`.
The reference stack ships three versions:

- `v1` — static RBAC (pre-risk-scoring baseline; kept for rollback).
- `v2` — risk-aware (current default; adaptive mask + deny thresholds).
- `v3` — v2 with stricter nurse redaction (adds `birthDate` to the
  baseline mask list, aligning the nurse-scope view with HIPAA Safe
  Harbor quasi-identifier handling).

`internal/policyversion.Manager` owns the set of bundles and the
"active" pointer. `internal/policy.OPAAdmin` talks to OPA's management
API (`PUT/DELETE /v1/policies/{id}`). The manager wires these together
so `Activate("vN")` and `Rollback()` both:

1. Read `policies/versions/<target>/authz.rego` from disk.
2. `PUT /v1/policies/authz` with that body.
3. Only after a 2xx from OPA, update the in-memory active pointer
   and history stack.

If step 2 fails the in-memory pointer is *not* advanced, so
`Manager.Active()` always matches the bundle OPA is actually serving —
critical for incident response ("what policy is running right now?")
and for idempotent retries. The `authz` OPA policy id is fixed per
manager instance, so every Activate/Rollback replaces the same module
and OPA's decision endpoint (`/v1/data/authz/decision`) immediately
reflects the new rules.

**Rollback workflow** (e.g. v3 causes legitimate traffic to be masked
too aggressively):

```
# Operator notices elevated fhir_proxy_policy_outcome_total{outcome="deny"}
# after a v3 rollout and wants to revert.
#
# From a controller / ops shim that owns the Manager:
manager.Rollback()       // → returns "v2", uploads v2/authz.rego to OPA
# If OPA is transiently unavailable, Rollback returns an error and the
# history stack is preserved — retrying after OPA recovers will
# successfully roll back without re-running any upstream bookkeeping.
```

The same flow is exercised in `internal/policyversion/manager_opa_test.go`
with an `httptest`-backed mock OPA — see `TestRollback_UploadsPreviousVersion`
and `TestRollback_PreservesHistoryOnOPAFailure`.

### FastAPI ML service (`ml/risk_service.py`)
Stateless HTTP service exposing:
- `POST /score`     — returns `{score, label, explanation}`
- `POST /feedback`  — persists reviewer verdicts for retraining
- `GET  /health`    — liveness

The service loads an IsolationForest pipeline from disk and optionally
wraps it with a SHAP `TreeExplainer` for per-feature attributions.

### Audit log
Append-only NDJSON file at `$AUDIT_LOG_FILE` (dev) or Azure Blob
(production). Each line carries the full context needed for forensic
replay: timestamp, tenant, subject, roles, path, status, reason,
redacted paths, and break-glass detail.

### Prometheus metrics
`/metrics` exposes:
- `fhir_proxy_requests_total`
- `fhir_proxy_request_duration_seconds`
- `fhir_proxy_upstream_duration_seconds`
- `fhir_proxy_policy_eval_duration_seconds`
- `fhir_proxy_policy_outcome_total{tenant,outcome,reason}`
- `fhir_proxy_risk_scores_total{label}`
- `fhir_proxy_risk_score_duration_seconds`
- `fhir_proxy_rate_limit_hits_total{tenant,subject,window}`
- `fhir_proxy_break_glass_total`
- `fhir_proxy_auth_failures_total`

## Multi-tenant isolation

The proxy runs as a single process but serves multiple hospitals (or
any set of independent OIDC realms) with strict cryptographic isolation
between them. The reference deployment carries two tenants end-to-end:
`hospital-a` and `hospital-b`.

### Identity boundary — verified `iss` claim is the only routing key

- Each tenant is identified by `issuer_url` in `configs/tenants.yaml`.
  The registry is keyed by issuer URL and rejects duplicate
  tenant ids/issuers at load time.
- A request is routed to a tenant ONLY via the cryptographically
  verified `iss` claim on the bearer JWT. There is no URL-based or
  header-based tenant selection — a client cannot "claim" a different
  tenant by setting `X-Tenant-Id` or targeting a different path.
- A token whose `iss` claim is absent from the registry is rejected
  with HTTP 401 `untrusted issuer` before any JWKS fetch, downstream
  handler, or OPA call runs.
- JWKS caches are per-tenant. The signing key for hospital-a is never
  used to verify a token that claims to come from hospital-b, even if
  both tenants are loaded in the same process.

### Keycloak — two realms, one container

`deployments/keycloak/` ships two realm exports:

- `realm-export.json`     → realm `hospital-a` with users
  `nurse1`, `doctor1`, `admin1` and client `fhir-privacy-proxy`.
- `realm-export-b.json`   → realm `hospital-b` with users
  `nurse-b1`, `doctor-b1`, `admin-b1` and client `fhir-privacy-proxy-b`.

Both files are mounted into the Keycloak container's
`/opt/keycloak/data/import` directory and loaded via `--import-realm`
at startup, giving each tenant its own realm, users, roles, signing
keys, and audience. Tokens from one realm are unusable against the
other.

### Policy data — per-tenant `data.json`

`policies/data.json` is structured as a map keyed by `tenant_id`:

```json
{
  "hospital-a": { "sensitive_patients": ["123", "999"] },
  "hospital-b": { "sensitive_patients": ["555", "777"] }
}
```

`policies/base/authz.rego` indexes into this map using the verified
tenant id on the subject:

```rego
is_sensitive_patient if {
    input.resource.patient_id in data[input.subject.tenant_id].sensitive_patients
}
```

Because `input.subject.tenant_id` comes from the signed JWT (resolved
by the registry, not provided by the caller), a hospital-a subject
cannot see hospital-b's sensitive list — the Rego expression literally
cannot reach `data["hospital-b"]` when the subject's verified tenant
is `hospital-a`. The lists are disjoint in the shipped data so that
regressions are caught: hospital-a's `123` and `999` must not appear
in hospital-b's list, and vice versa.

### Proof

`cmd/proxy/tenant_isolation_test.go` is the standing proof of this
isolation claim. It stands up two mock JWKS servers (one per tenant)
and exercises the real auth middleware + OPA input path to verify:

1. A token whose issuer isn't registered is rejected with 401
   `untrusted issuer`.
2. `SubjectContext.TenantID` is derived from the verified `iss`
   claim — client-supplied `X-Tenant-Id` / `X-Forwarded-Tenant`
   headers are ignored.
3. A token whose `iss` points at hospital-b but is signed with
   hospital-a's key fails signature verification (cross-issuer
   forgery).
4. `policies/data.json` per-tenant sensitive lists are disjoint and
   the `data[input.subject.tenant_id].sensitive_patients` indexing
   keeps each tenant's list unreachable from the other.

## Data flow for a single request

1. Client calls `GET /fhir/r4/Patient/123` with a bearer JWT.
2. Proxy validates the JWT, extracts roles, department, and scopes.
3. Proxy verifies `patient/Patient.read` is in the token scopes.
4. Proxy calls the FastAPI service with the request features.
5. Proxy calls OPA with the full context; OPA returns `allow=true,
   remove=[identifier], mask=[telecom, address]`.
6. Proxy forwards the GET to HAPI FHIR.
7. Proxy applies the remove/mask lists to the response (Bundle-aware).
8. Proxy writes the redacted JSON back to the client.
9. Proxy appends an audit line and updates Prometheus counters.
