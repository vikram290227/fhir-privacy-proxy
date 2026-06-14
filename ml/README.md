# AI Risk Scoring Module

> **Model maturity: pipeline validation only.**
> The IsolationForest is trained exclusively on synthetic data generated
> by `generate_synthetic_data.py`. AUC figures from `ml/tests/` reflect
> how well the model fits its own generator — not real clinical access
> patterns. Do **not** treat those numbers as deployment-readiness
> signals. Before production use, seed the training set with at least
> 90 days of real audit logs and validate against a held-out real split.

This directory contains the Python ML layer that turns the FHIR
Privacy Proxy into an adaptive, AI-aware access-control system.

## Architecture

```
┌──────────────┐     /score     ┌──────────────────┐
│  Go Proxy    │ ─────────────▶ │  FastAPI Service │
│ (ScoreRisk   │                │  risk_service.py │
│  middleware) │ ◀───────────── │                  │
└──────────────┘   risk score   └─────────┬────────┘
                                          │
                                          ▼
                                  ┌────────────────┐
                                  │ IsolationForest│
                                  │  + SHAP        │
                                  │ iforest.joblib │
                                  └────────────────┘
```

The Go proxy invokes the service **before** OPA, attaches the returned
`risk.score` to the subject context, and OPA uses it to pick between
`allow`, `mask`, and `deny` decisions (see `policies/base/authz.rego`).

## Files

| File | Purpose |
|---|---|
| `schema.py` | Access-log schema + feature columns shared with the Go client |
| `generate_dataset.py` | Synthetic healthcare access-log generator |
| `train_isolation_forest.py` | Trains the IsolationForest pipeline + saves joblib |
| `risk_service.py` | FastAPI service exposing `/score`, `/feedback`, `/health`, `/metrics` |
| `retrain_nightly.py` | Nightly retraining job — merges feedback NDJSON back into the training set and atomically replaces the joblib |
| `feedback_loop.md` | Design for the supervised retraining loop |
| `tests/test_retrain.py` | Pytest coverage for `retrain_nightly.py` |
| `requirements.txt` | Python dependencies |

## Quick start

```bash
# 1. Install dependencies
pip install -r ml/requirements.txt

# 2. Generate a synthetic training set (20k rows, ~2% anomalies)
python ml/generate_dataset.py --rows 20000 --out ml/data/access_logs.csv

# 3. Train the Isolation Forest
python ml/train_isolation_forest.py \
    --input ml/data/access_logs.csv \
    --model ml/models/iforest.joblib

# 4. Run the FastAPI service
uvicorn ml.risk_service:app --host 0.0.0.0 --port 8000

# 5. Point the Go proxy at it
export RISK_SERVICE_URL=http://localhost:8000
```

## Feature set

| Feature | Description |
|---|---|
| `hour` | Hour of day the access occurred (0-23) |
| `day_of_week` | 0=Sun .. 6=Sat |
| `break_glass` | 1 if emergency override used |
| `patient_sensitive` | 1 if accessing a flagged sensitive patient |
| `department_match` | 1 if subject's department == patient's dept |
| `role` | nurse / doctor / admin |
| `action` | read / write |
| `resource_type` | Patient / Observation / Condition / ... |

## Response format

```json
{
  "score": 0.83,
  "label": "anomalous",
  "explanation": {
    "unusual_hour": 0.4,
    "department_mismatch": 0.35
  }
}
```

`label` is derived from `score`:

| Score range | Label | Adaptive policy action |
|---|---|---|
| `< 0.6` | `normal` | allow (role-based redaction only) |
| `0.6 – 0.85` | `suspicious` | allow but widen masking |
| `>= 0.85` | `anomalous` | deny (unless break-glass) |

Thresholds live in `policies/base/authz.rego` and can be tuned per tenant.

## Risk score action tiers and `threshold_floor`

The ML score drives OPA decisions through configurable thresholds
(`risk_deny_threshold`, `risk_mask_threshold` in `authz.rego`).
For v1 deployments the **recommended default is log-only** — the score
is attached to the audit record and surfaced in the Privacy Officer
dashboard, but does not block or widen masking until the model has been
validated on real data.

The `threshold_floor` concept: set `risk_deny_threshold = 1.1` (above
the maximum possible score of 1.0) and `risk_mask_threshold = 1.1` to
put the model into advisory mode. Scores still appear in Prometheus
(`risk_score` histogram) and in the structured log so Privacy Officers
can review flagged events without clinicians experiencing false-positive
denials.

When validation on real data reaches acceptable precision, lower the
thresholds in `authz.rego` to activate blocking/masking.

## Feedback + nightly retraining

The detector only stays useful if it learns from reviewer decisions.
See `feedback_loop.md` for the full design; the short version:

1. The proxy calls `/score` on every authorized request. The returned
   label lands in the audit log.
2. A reviewer POSTs a verdict to `/feedback` for any decision they
   want to reinforce or correct. The service appends the record to
   `ml/data/feedback.ndjson`.
3. `ml/retrain_nightly.py` merges the NDJSON back into the training
   set on a cron / scheduled-action, atomically replaces
   `ml/models/iforest.joblib`, and writes a sidecar
   `iforest.joblib.meta.json` with `{training_rows, feedback_rows,
   anomaly_rate, last_trained_ts}`.
4. `risk_service.py` watches the joblib mtime (30s poll by default,
   override with `MODEL_POLL_SECS`) and hot-reloads the pipeline in
   place — no uvicorn restart needed. On reload it re-reads the
   sidecar and publishes the gauges on `/metrics`.

### Retraining on demand

```bash
python ml/retrain_nightly.py \
    --input ml/data/access_logs.csv \
    --feedback ml/data/feedback.ndjson \
    --model ml/models/iforest.joblib
```

Sample output:

```
rows trained:       20003
feedback ingested:  1
anomaly rate:       0.0208
model path:         ml/models/iforest.joblib
last trained (unix): 1729180800
```

### Feedback rows

Each NDJSON line is what the FastAPI service writes from
`POST /feedback`:

```json
{
  "user_id": "nurse7",
  "role": "nurse",
  "resource_type": "Observation",
  "action": "write",
  "hour": 2,
  "day_of_week": 6,
  "department_match": false,
  "break_glass": false,
  "patient_sensitive": true,
  "was_legitimate": false,
  "reviewer": "secops@example.com",
  "timestamp": "2025-11-14T02:07:08.812Z"
}
```

- `was_legitimate: true` — model flagged but reviewer approved. The
  row is injected into training **unchanged** so the detector sees
  this vector as an inlier on the next fit.
- `was_legitimate: false` — model allowed but was actually anomalous.
  The row is injected **3×** with Gaussian noise on `hour` /
  `day_of_week` (clamped to legal ranges) so the decision boundary
  bends toward reviewer intent without overfitting a single point.

A single corrupt NDJSON line is logged and skipped, not fatal — the
retrain is designed to be safe to run unattended on a cron.

### Scheduled job

`.github/workflows/retrain.yml` is a scaffold that runs
`retrain_nightly.py` at 02:00 UTC daily (also via
`workflow_dispatch`). It seeds a synthetic training set if none is
checked in and publishes the resulting joblib as a build artifact.
Before production use, replace the synthetic-seeding step with a pull
from your durable store (S3 / Azure Blob / GCS) and add an equivalent
push on the way out.

### Metrics

`GET /metrics` exposes Prometheus gauges that operators can alert on:

| Gauge | Meaning |
|---|---|
| `risk_model_training_rows` | Rows used for the last fit (incl. feedback injections) |
| `risk_model_anomaly_rate` | Share of training rows scored ≥ 0.6 (`suspicious` threshold) |
| `risk_model_feedback_rows` | Feedback NDJSON records ingested last run |
| `risk_model_last_trained_ts` | Unix timestamp of the last successful retrain |

### Tests

```bash
pip install -r ml/requirements.txt pytest
pytest ml/tests/
```

The tests synthesise a tiny CSV + NDJSON, run a full retrain cycle,
and verify the resulting joblib predicts on fresh vectors — which is
the invariant the service depends on across a model swap.
