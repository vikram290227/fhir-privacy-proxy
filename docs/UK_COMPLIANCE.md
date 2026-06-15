# UK Compliance Assessment

## DSPT (Data Security and Protection Toolkit)

The DSPT is an annual self-assessment against 10 standards published by NHS England.
The table below maps each standard to the controls this proxy implements.

| # | Standard | Control implemented | Gap |
|---|---|---|---|
| 1 | Personal confidentiality and data protection | JWT validation, OPA policy, purpose-of-use header, field-level masking | None |
| 2 | Staff responsibilities | Role extraction from CIS2 / Keycloak; roles drive OPA decisions | Training records are outside proxy scope — governance team |
| 3 | Training | Roles validated on every request; `has_roles` gate in authz.rego | Completion tracking outside proxy scope |
| 4 | Managing data access | Per-tenant allowed_scopes, scope-intersection check in middleware.go | None |
| 5 | Process reviews | Audit log written for every decision; ML feedback loop for anomaly review | Formal review cadence is an operational process |
| 6 | Responding to incidents | Break-glass logged at WARN level; jti revocation via Redis | Incident response playbook outside proxy scope |
| 7 | Continuity planning | Redis rate-limiter degrades gracefully (fail-open); ML timeout fail-open | Formal DR plan outside proxy scope |
| 8 | Unsupported systems | No EOL dependencies in go.mod / requirements.txt at time of writing | Review annually |
| 9 | IT protection | TLS at network boundary (assumed at load balancer / ingress) | mTLS between proxy and upstream FHIR not yet implemented |
| 10 | Audit | Structured JSON audit log, Prometheus metrics, OPA decision trail | Long-term retention store (S3/Splunk) wiring is operator responsibility |

**Overall posture:** Standards 1, 4, 6 are substantially met by proxy controls.
Standards 2, 3, 5, 7, 8, 10 require complementary operational and governance processes outside this codebase.
Standard 9 has a documented gap (mTLS to upstream) that should be tracked in the infrastructure backlog.

---

## DTAC (Digital Technology Assessment Criteria) Self-Assessment

DTAC covers five domains. This assessment is a gap analysis, not a submission.

### Domain 1 — Clinical Safety

| Criterion | Status | Notes |
|---|---|---|
| Named Clinical Safety Officer (CSO) | **MISSING — people gap** | DCB0129 / DCB0160 require a named, qualified CSO. This is a hiring or contracting need, not a documentation gap. A part-time clinical advisor with HSCIC clinical safety training is the minimum. |
| Clinical Risk Management System (CRMS) | Not started | Requires DCB0129 Hazard Log and Clinical Risk Management Plan. |
| DCB0129 Hazard Log | **Not created** | Must enumerate all identified hazards, severity, likelihood, and mitigations before clinical go-live. |
| DCB0160 Clinical Safety Case | **Not created** | Formal sign-off by CSO that residual risk is acceptable. |
| Fail-safe behaviour | Implemented | ML scoring fails open (risk unavailable → OPA advisory only). Break-glass bypasses tier-1 counters. |
| Audit trail for clinical access | Implemented | Structured log on every OPA decision including `purpose_of_use`. |

**Action required before clinical go-live:**
1. Appoint a named CSO.
2. Commission a DCB0129 Hazard Log covering at minimum: incorrect field masking leading to clinical error; false-positive access deny during emergency; sensitive-patient list out of sync.
3. Obtain DCB0160 sign-off from CSO.

### Domain 2 — Data Protection

| Criterion | Status |
|---|---|
| UK GDPR Article 25 (privacy by design) | Met — default-deny OPA policy, field-level masking, purpose-of-use enforcement |
| Data Processing Agreement template | Out of scope for this codebase — legal team |
| Data Protection Impact Assessment (DPIA) | Not created — must be produced per deployment |
| ICO registration | Operator responsibility |

### Domain 3 — Technical Security

| Criterion | Status |
|---|---|
| OWASP Top 10 | RS256 JWT validation, no SQL/NoSQL injection surface, structured error responses (no stack traces) |
| Penetration test | Not performed — required before production |
| NCSC Cyber Essentials | Operator infrastructure responsibility |
| Dependency vulnerability scanning | Not automated — add `govulncheck` / `pip-audit` to CI |

**Recommended additions:**
- `govulncheck ./...` in CI pipeline
- `pip-audit -r ml/requirements.txt` in CI pipeline
- Scheduled pen test against staging environment

### Domain 4 — Interoperability

| Criterion | Status |
|---|---|
| FHIR R4 conformance | Proxy is FHIR-agnostic — upstream server provides conformance |
| NHS login / CIS2 integration | CIS2 tenant supported via `cis2_mapper.go`; JWKS validated against OpenAM |
| INTEROPen / HL7 UK membership | Not applicable to a proxy layer |
| SNOMED CT / dm+d binding | Upstream server responsibility |

### NHS PDS Sandbox Registration

To wire this proxy against the NHS Personal Demographics Service (PDS) FHIR R4 sandbox:

1. **Create an NHS Digital developer account** at <https://digital.nhs.uk/developer>.
2. **Register a new application** in the NHS API Management portal and select the
   *Personal Demographics Service — FHIR API* product.
3. **Generate an API key** (displayed once — copy it immediately).
4. **Set environment variables** (copy `.env.example` and populate):
   ```
   NHS_PDS_FHIR_URL=https://sandbox.api.service.nhs.uk/personal-demographics/FHIR/R4
   NHS_API_KEY=<your-api-key>
   FHIR_UPSTREAM=${NHS_PDS_FHIR_URL}
   ```
5. **Start the proxy** — the `apikey` header is injected on every upstream
   request when `NHS_API_KEY` is set (`cmd/proxy/main.go`, `fhirProxyHandler`).
6. **Smoke test:**
   ```bash
   curl -H "Authorization: Bearer <jwt>" \
        http://localhost:8080/fhir/r4/Patient/9000000009
   ```
   The sandbox NHS number `9000000009` is seeded by NHS Digital and should
   return a synthetic patient record.

> **Production notes:** PDS production requires PKCE OAuth2 / CIS2 token exchange
> (not an API key). The `NHS_API_KEY` path is sandbox-only. For production, issue
> tokens via the CIS2 `cis2` tenant configuration and leave `NHS_API_KEY` unset.

### Domain 5 — Usability and Accessibility

| Criterion | Status |
|---|---|
| WCAG 2.1 AA | No UI surface in this proxy — N/A |
| NHS Service Manual | N/A — API-only component |
| User research | N/A |

---

## Summary Gap Table

| Gap | Severity | Owner |
|---|---|---|
| No named Clinical Safety Officer | **Critical** — blocks clinical go-live | HR / CTO |
| No DCB0129 Hazard Log | **Critical** — blocks clinical go-live | CSO once appointed |
| No DCB0160 Clinical Safety Case | **Critical** — blocks clinical go-live | CSO once appointed |
| No pen test | High | Security team |
| No DPIA | High | Legal / DPO |
| No govulncheck / pip-audit in CI | Medium | DevOps |
| mTLS to upstream FHIR not implemented | Medium | Infrastructure |
| Standard 9 (mTLS) not met | Medium | Infrastructure |

The proxy codebase is **pre-clinical**: suitable for sandbox integration testing with NHS CIS2 and
for non-clinical administrative use cases. Clinical production deployment requires the three CSO
deliverables above before submission to NHS Digital / ICB for go-live approval.
