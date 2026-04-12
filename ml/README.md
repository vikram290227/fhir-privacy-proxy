# AI Risk Scoring Module

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
| `risk_service.py` | FastAPI service exposing `/score`, `/feedback`, `/health` |
| `feedback_loop.md` | Design for the supervised retraining loop |
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
