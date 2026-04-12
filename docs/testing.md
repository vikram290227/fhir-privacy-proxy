# End-to-End Test Plan

This document maps the external tooling ecosystem (HAPI public, Synthea,
Inferno, Touchstone) to concrete commands against this proxy. Every
phase below assumes the stack is already running:

```bash
make up            # brings up keycloak, opa, fhir, risk, proxy
```

## Phase 1 — Connectivity

Goal: confirm the Go proxy can pass FHIR traffic to an upstream and
apply role-based redaction.

```bash
./scripts/demo.sh
```

Expected:
- nurse → identifier REMOVED, telecom+address MASKED
- doctor → identifier VISIBLE, address MASKED
- admin → all fields VISIBLE
- nurse + break-glass → full access, audited as BREAK_GLASS

### Swapping upstream to the public HAPI sandbox

Point the proxy at `http://hapi.fhir.org/baseR4` instead of the bundled
container:

```bash
# In deployments/docker/docker-compose.yml (proxy service env)
FHIR_UPSTREAM: http://hapi.fhir.org/baseR4
```

Then rebuild:

```bash
make down && make up
```

Caveats:
- The public HAPI server does not carry your Keycloak IDs — you'll need
  to adjust `policies/data.json` sensitive_patients to known public IDs
  or just exercise the redaction pipeline on any GET.
- POST/seed steps in `scripts/demo.sh` may fail or rate-limit; skip them.

## Phase 2 — Policy Check (role-based redaction + sensitive patients)

Goal: confirm OPA correctly masks sensitive patient fields.

1. Seed a patient with `scripts/demo.sh` and note the returned ID.
2. Add the ID to `policies/data.json` under `sensitive_patients`.
3. Re-run the nurse call — expect `403 access_denied`.
4. Re-run with `X-Break-Glass: true` + justification — expect `200`
   and an `audit.ndjson` entry with `break_glass.enabled=true`.

## Phase 3 — AI Risk Engine

Goal: exercise the IsolationForest via both the proxy and direct
FastAPI calls.

```bash
./scripts/attack_sim.sh
```

What it does:

| Phase | Target | Mechanism |
|---|---|---|
| 1 Baseline | proxy | nurse/GET at current time |
| 2 Bulk extraction | proxy | 100 back-to-back GETs |
| 3 Sensitive snooping | proxy | nurse → VIP patient, with + without break-glass |
| 4 Out-of-hours | direct /score | hour=3 (can't spoof proxy clock) |
| 5 Dept mismatch | direct /score | department_match=false |
| 6 Sensitive + no BG | direct /score | patient_sensitive=true, break_glass=false |

Expected movements:

- out-of-hours → label `suspicious` (≥ 0.6)
- department mismatch → `suspicious`
- VIP + no break-glass + late hour → `anomalous` (≥ 0.85)
- VIP + break-glass → still elevated, allowed, audited

### Synthea-driven dataset swap

To replace the synthetic training set with Synthea output:

```bash
# 1. Generate Synthea bundles (outside this repo)
java -jar synthea-with-dependencies.jar -p 500 -s 12345

# 2. Convert to CSV that matches ml/schema.py (write your own adapter)

# 3. Retrain
python ml/train_isolation_forest.py \
    --input your_synthea.csv \
    --model ml/models/iforest.joblib

# 4. Restart the risk container
docker compose restart risk
```

## Phase 4 — SMART-on-FHIR Compliance

Goal: confirm the proxy does not break FHIR conformance while enforcing
its policies.

Inferno is the HealthIT.gov conformance suite. Point it at the proxy:

```
Fhir Server URL:  http://localhost:8080/fhir/r4
Client ID:        fhir-privacy-proxy
Token Endpoint:   http://localhost:8180/realms/hospital-a/protocol/openid-connect/token
Authorize URL:    http://localhost:8180/realms/hospital-a/protocol/openid-connect/auth
JWKS URL:         http://localhost:8180/realms/hospital-a/protocol/openid-connect/certs
```

The proxy should pass the baseline "SMART v1 bearer token" tests. Any
capability-statement probes may 404 because the proxy only serves
`/fhir/r4/{ResourceType}` — whitelist those paths or point Inferno at
the upstream HAPI directly for capability checks.

## Phase 5 — Break-glass forensic replay

Goal: prove the audit trail is complete enough for a compliance
officer.

```bash
# Trigger a break-glass event
./scripts/attack_sim.sh       # phase 3 already runs this

# Pull the audit log
docker compose exec proxy cat /app/audit/audit.ndjson | tail -5
```

Every break-glass entry should carry:
- `break_glass.enabled = true`
- `break_glass.justification` (non-empty)
- `subject.subject_id` and `subject.roles`
- `request.path` and `request.method`
- `policy.reason` and `policy.remove/mask` lists
- `risk.score` and `risk.label`

## Metrics-driven verification

While the attack simulation runs, scrape Prometheus:

```bash
curl -s http://localhost:8080/metrics | grep fhir_proxy_
```

Watch these counters move:
- `fhir_proxy_policy_outcome_total{outcome="allow"}` rises during phase 1
- `fhir_proxy_policy_outcome_total{outcome="deny",reason="high_risk_denied"}` rises during phase 3 / 6
- `fhir_proxy_risk_scores_total{label="suspicious"}` rises during phases 4-5
- `fhir_proxy_risk_scores_total{label="anomalous"}` rises during phase 6
- `fhir_proxy_break_glass_total` rises when phase 3 break-glass fires
