# Security Architecture — Tiered Authorization Model

> **Last updated:** 2026-06-14  
> **Status:** Tiers 0–2 implemented, Tier 3 async pipeline in roadmap

## Overview

Authorization is enforced through three tiers that fire **in sequence on every request**. A request is denied as soon as any tier fires — it never reaches a more expensive downstream check.

```
Incoming request
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  Tier 0 — Token validation + SMART scope check          │
│  Cost: <1 ms  |  Sync  |  auth.ValidateToken            │
└──────────────────────────┬──────────────────────────────┘
                           │ pass
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Tier 1a — Rate-limit 429 (Redis sliding window)        │
│  Cost: ~1 ms  |  Sync  |  Hard reject → 429             │
│  auth.RateLimit → Redis Lua (minute + hour + day)       │
└──────────────────────────┬──────────────────────────────┘
                           │ allowed; access_counts attached
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Tier 2 — ML risk score (FastAPI, 15 ms hard timeout)   │
│  Cost: 2–15 ms  |  Sync  |  score → SubjectContext      │
│  On timeout/error: Unavailable=true, Tier 1b takes over │
└──────────────────────────┬──────────────────────────────┘
                           │ score attached
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Tier 1b — OPA hard rules (counter-based, no ML)        │
│  Cost: ~3 ms  |  Sync  |  policies/base/authz.rego      │
│  tier1_deny: hour > 100, after-hours > 20, day > 500    │
│  bulk_deny:  $everything or _count > 200 (bulk_access)  │
│  Fires independently of whether ML is available.        │
└──────────────────────────┬──────────────────────────────┘
                           │ pass
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Tier 2b — OPA adaptive rules (uses ML score)           │
│  Included in same OPA call as Tier 1b                   │
│  score ≥ 0.85 → deny  |  score ≥ 0.60 → mask PII       │
└──────────────────────────┬──────────────────────────────┘
                           │ allow + redaction instructions
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Tier 3 — Async deep analysis (NOT on request path)     │
│  SHAP explanations, 30-day peer deviation, retraining   │
│  Feeds Privacy Officer dashboard + future rule updates  │
└─────────────────────────────────────────────────────────┘
```

---

## Tier 1a — Redis Sliding-Window Rate Limiter

**`internal/ratelimit/ratelimit.go`**

Three independent windows per `(tenant_id, subject_id)`, enforced atomically via a single Lua script:

| Window | Redis key | Limit source | Hard reject at Redis? |
|--------|-----------|-------------|----------------------|
| Minute | `:min` | tenants.yaml / default | Yes → 429 |
| Hour | `:hour` | tenants.yaml / default | Yes → 429 |
| Day | `:day` | count-only (limit=0) | No — OPA enforces |

The day window is always recorded but the Redis layer never rejects on it. Its count is surfaced as `input.subject.access_counts.last_day` so OPA Tier 1b can apply a daily threshold without a second Redis call.

When Redis is unavailable the middleware fails open with a warning log — the ML + OPA layers remain the backstop.

---

## Tier 2 — ML Risk Scoring

**`internal/risk/client.go`, `internal/auth/risk.go`**

Calls FastAPI synchronously before OPA, with a **15 ms hard deadline** (`risk.ScoreTimeout`).

```
Success:  Risk.Score = <model output>,  Risk.Unavailable = false
Timeout:  Risk.Score = 0,               Risk.Unavailable = true
Error:    Risk.Score = 0,               Risk.Unavailable = true
```

When `Unavailable=true`, OPA's `risk_score` defaults to 0 (neutral — not "safe"). Tier 1b counter rules still apply independently.

**Metric:** `fhir_proxy_ml_timeouts_total{tenant_id}` — a sustained high rate (>1% of scored requests) is the operational signal to switch to the ONNX-embedded path (see §ONNX Roadmap).

---

## Tier 1b — OPA Counter-Based Hard Rules

**`policies/base/authz.rego`**

Fire regardless of ML availability, using only Redis counters computed in Tier 1a:

```rego
tier1_deny if { access_counts.last_hour > 100 }                        # any user
tier1_deny if { is_after_hours AND last_hour > 20 AND not admin }      # off-hours cap
tier1_deny if { access_counts.last_day > 500 }                         # daily cap
```

Break-glass bypasses Tier 1b by design — the break-glass `allow` rule has no `not tier1_deny` condition.

---

## Bulk-Bundle Detection

**`policies/base/bulk_access.rego`**

Catches the specific exfiltration scenario — a user pulling a massive bulk patient bundle — with a synchronous, ML-independent rule:

| Signal | Threshold | Action |
|--------|-----------|--------|
| Path ends with `/$everything` | any | `bulk_deny` (unless break-glass) |
| `_count` query param | > 200 | `bulk_deny` (unless break-glass) |
| List operation (GET, no resource ID) | any | `bulk_warn` (audit only) |

`bulk_deny` is referenced in `authz.rego` as `data.firewall.bulk_access.bulk_deny` and blocks both the normal clinical and admin `allow` rules. Break-glass users can override. `bulk_warn` is returned in the OPA result for Privacy Officer dashboard visibility without blocking the request.

---

## Tier 2b — OPA Adaptive Rules

**`policies/base/authz.rego`**

When ML score is available:

| Score range | Action |
|-------------|--------|
| < 0.60 | Allow; mask `$.identifier[0].value` only (for non-admin) |
| 0.60–0.85 | Allow; mask `$.telecom`, `$.address`, `$.identifier`, `$.birthDate` |
| ≥ 0.85 | Deny (`reason: high_risk_denied`) |

When `Unavailable=true`: `risk_score` is 0 and only Tier 1b rules apply.

---

## Tier 3 — Async Deep Analysis

**Status:** Partially implemented (`ml/retrain_nightly.py`, `ml/feedback_loop.md`)

Tier 3 is explicitly **not on the request path** — async here is correct:

- **30-day peer deviation:** Batch job comparing a user's pattern against role cohort.
- **SHAP explanations:** Generated for anomalous-scored requests, appended to audit log.
- **Nightly retraining:** `ml/retrain_nightly.py` ingests Privacy Officer feedback from `ml/data/feedback.ndjson` and hot-reloads the updated model into the FastAPI service.

Tier 3 outputs tighten Tier 1 thresholds and improve Tier 2 model quality over time. They never touch real-time blocking.

---

## ONNX Embedding Roadmap (Task 2.4)

The current Tier 2 makes a network hop to FastAPI. Measured loopback latency: 2–15 ms against the 15 ms budget.

The alternative is embedding the ONNX-exported model directly in Go:

```bash
# Export (requires: pip install skl2onnx)
python ml/export_onnx.py --model ml/models/iforest.joblib \
                          --output ml/models/risk_model.onnx

# Go runtime (requires: CGO + ONNX Runtime shared library)
# github.com/yalue/onnxruntime_go
```

| Approach | p50 latency | p99 latency | Timeout risk |
|----------|------------|------------|-------------|
| FastAPI loopback (current) | ~3 ms | ~14 ms | Yes at 15 ms |
| ONNX in-process (estimated) | ~80 µs | ~200 µs | None |

The ONNX path is ~40× faster and eliminates the `Unavailable` fallback path entirely. Implement when `fhir_proxy_ml_timeouts_total` exceeds 1% of scored requests in production.

---

## Middleware Execution Order

`cmd/proxy/main.go` lines 285–297:

```
ValidateToken      JWT signature + expiry + tenant lookup
RequireSmartScope  SMART-on-FHIR scope enforcement
RateLimit          Redis 429; surfaces access_counts to context
ScoreRisk          ML score (15 ms timeout); sets Risk + IsAfterHours
CheckConsent       FHIR Consent resource lookup (5-min LRU cache)
EnforcePolicy      OPA: Tier1b + bulk_access + adaptive rules
fhirProxyHandler   Upstream call + field-level redaction from OPA result
```

Each middleware reads from and writes to `auth.SubjectContext` stored in the request context. OPA receives the fully-populated struct as `input.subject`.
