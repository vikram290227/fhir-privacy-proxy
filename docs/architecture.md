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
3. **ScoreRisk** — calls the Python FastAPI service, attaches the
   returned score, label, and SHAP-style explanation to the subject
   context. Falls back to score=0 if the service is unreachable.
4. **EnforcePolicy** — POSTs the full subject + request + resource
   context to OPA, receives an allow/deny + remove/mask lists, and
   records the decision in Prometheus.
5. **fhirProxyHandler** — forwards the request to the upstream FHIR
   server, reads the JSON response, applies redactions (single
   resources and Bundles including nested bundles), then writes the
   response. An audit event is asynchronously appended to NDJSON.

### OPA (`policies/base/authz.rego`)
Rule engine. Reads `input.subject`, `input.request`, `input.resource`,
`input.subject.risk.score` and returns `allow`, `remove`, `mask`,
`reason`, `risk_score`. Thresholds:

- `risk_mask_threshold = 0.6`  → widen mask list
- `risk_deny_threshold = 0.85` → deny unless break-glass

Versioned bundles live under `policies/versions/` and are managed by
`internal/policyversion` (rollback supported).

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
- `fhir_proxy_break_glass_total`
- `fhir_proxy_auth_failures_total`

## Multi-tenant isolation

- Each tenant is identified by `issuer_url` in `configs/tenants.yaml`.
- JWKS caches, policy bundles, and OPA data files are scoped per
  tenant. A request is routed to its tenant only via the verified
  `iss` claim — there is no URL-based tenant selection, preventing
  cross-tenant impersonation.
- The registry rejects duplicate tenant ids/issuers at load time.

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
