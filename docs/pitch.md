# AI-Powered FHIR Privacy Proxy — Pitch

## The problem

Healthcare systems expose FHIR APIs to every clinical app, analytics
pipeline, and partner integration. Today's access-control story is
brittle:

1. **Role-based rules are static.** A nurse either can read Patient or
   can't. There's no room for "you can read during a cardiac arrest
   but not at 3am on a Sunday".
2. **Field-level redaction is hand-rolled.** Teams reinvent masking
   per endpoint, producing inconsistent responses and untestable
   one-offs.
3. **Sensitive-patient leaks are insider-driven.** 58% of healthcare
   breaches involve authorised users. Static RBAC can't catch a
   credentialed doctor pulling celebrity records.
4. **Audit is an afterthought.** Most orgs log that a request
   happened, not what was masked, why the decision was made, or
   whether break-glass was justified.

## The solution

A **policy-engine + AI risk-scoring proxy** that sits in front of any
FHIR server and enforces:

- **SMART-on-FHIR authentication** with per-tenant JWKS
- **Scope enforcement** (HTTP method → required scope)
- **Role and context-aware redaction** (remove/mask) via OPA Rego
- **Break-glass override** with justification + mandatory audit
- **AI risk scoring** (Isolation Forest + SHAP) in the request path
- **Adaptive policy** — risk score tightens or loosens masking in
  real time
- **Versioned policies** with rollback
- **Per-tenant isolation** with zero cross-tenant bleed
- **Persistent audit** (NDJSON / Azure Blob) including break-glass
  justification and redacted field lists

## Architecture (in one picture)

```
Client → [JWT] → Go Proxy ──▶ FastAPI ML ─┐
                    │                      │
                    │◀── risk score ───────┘
                    ▼
                   OPA ──▶ allow / mask / deny
                    │
                    ▼
              Redacted FHIR
```

## Differentiator: the AI layer

The risk-scoring model turns every access attempt into a feature
vector (role, department, hour, break-glass, resource, patient
sensitivity, weekday) and runs it through an unsupervised Isolation
Forest. The SHAP wrapper returns **why** the score was elevated, so
reviewers can spot drift in under a second.

Adaptive policy uses two thresholds:

| Score | Outcome |
|---|---|
| < 0.6 | normal — role-based redaction only |
| 0.6 – 0.85 | suspicious — extra masking (identifier + birthDate) |
| ≥ 0.85 | anomalous — deny unless break-glass |

Every scored event flows into an append-only log, and reviewer
verdicts feed a **supervised feedback loop** that retrains the model
nightly. The system gets more accurate the longer it's deployed.

## Market opportunity

- **Who buys**: US health systems (HIPAA), EU providers (GDPR), FHIR
  API vendors (Epic, Cerner, Oracle Health integrators), healthcare
  analytics (Komodo, Flatiron, Truveta), and regulated AI vendors
  who need BAA-compatible access control.
- **Market size**: Healthcare cybersecurity is projected to reach
  $58B by 2030. The "API access control + DLP" sub-segment is the
  fastest-growing slice, with FHIR-native tools almost non-existent.
- **Beachhead**: independent clinics and healthtech startups who
  need instant SMART-on-FHIR compliance without hiring a security
  team — drop the proxy in front of HAPI FHIR and ship.
- **Expansion**: large IDNs that need adaptive risk scoring across
  tens of millions of requests/day with SHAP explainability for
  their compliance officers.

## Why now

1. **FHIR is mandatory.** ONC Rule + EU EHDS are making FHIR APIs
   mandatory for payers and providers, creating a net-new attack
   surface.
2. **Insider-threat is measurable.** 2024 HIMSS survey puts insider
   incidents at 58% of all breaches.
3. **LLM-driven healthcare apps** need risk-aware access. A
   hallucinating clinical LLM fetching 10,000 patient records is a
   compliance disaster waiting to happen.

## Competitive landscape

| Category | Competitor | Our edge |
|---|---|---|
| API gateways | Kong, Apigee | No FHIR awareness, no field-level redaction |
| OPA integrators | Styra | No AI, no SMART-on-FHIR, no audit depth |
| DLP | Bigid, Immuta | Batch-oriented, no in-request enforcement |
| Healthcare IAM | Okta, Ping | Authentication only, no policy enforcement |

Nobody else ships AI risk scoring **in the request path** with SHAP
explainability and adaptive OPA policies out of the box.

## Call to action

Deploy the proxy in 10 minutes:

```bash
git clone github.com/vikram290227/fhir-privacy-proxy
cd fhir-privacy-proxy
make up
./scripts/demo.sh
```

You now have: SMART-on-FHIR auth, OPA policy enforcement, field-level
redaction, break-glass audit, Prometheus metrics, and an AI risk
scorer — all wired end-to-end.
