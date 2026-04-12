# ML Feedback Loop Design

The anomaly detector only stays accurate if it learns from reviewer
decisions. This document describes how supervised feedback is
collected, stored, and merged back into the next training cycle.

## Data flow

```
┌──────────────┐  decision   ┌──────────────┐  audit log  ┌──────────────┐
│  Go Proxy    │ ──────────▶│ audit_file   │────────────▶│  Reviewer UI │
└──────────────┘             └──────────────┘              └──────┬───────┘
                                                                  │ verdict
                                                                  ▼
                                                         ┌────────────────┐
                                                         │ FastAPI        │
                                                         │ POST /feedback │
                                                         └───────┬────────┘
                                                                 ▼
                                                         ┌────────────────┐
                                                         │ feedback.ndjson│
                                                         └───────┬────────┘
                                                                 ▼
                                                   ┌────────────────────────┐
                                                   │ retrain_nightly.py     │
                                                   │ (cron / scheduled job) │
                                                   └───────┬────────────────┘
                                                           ▼
                                                 ┌────────────────────┐
                                                 │ iforest.joblib v++ │
                                                 └────────────────────┘
```

## Lifecycle

1. **Inference** — the proxy calls `/score` and attaches the `risk_score`
   to the OPA input. The returned label plus all input features are
   written into the audit log (`audit_file`).
2. **Review** — a human reviewer inspects the access event and decides
   whether the decision was correct. The verdict is POSTed to
   `/feedback` on the FastAPI service.
3. **Storage** — `/feedback` appends an NDJSON record to
   `ml/data/feedback.ndjson`. Each record carries the original
   features plus a `was_legitimate` boolean and the reviewer id.
4. **Retraining** — a nightly job (`retrain_nightly.py`, to be scheduled
   via cron or a GitHub Action) loads:
   - The original training CSV
   - New rows from the audit log converted to the same schema
   - The feedback NDJSON (used to weight rows, not relabel them)
   It retrains the Isolation Forest pipeline, writes the new joblib to
   `iforest.joblib.next`, and atomically renames it to the active file.
5. **Promotion** — the FastAPI service is configured to watch the
   joblib mtime and reload when it changes, giving the system a
   zero-downtime model swap.

## Weighting feedback

Isolation Forest is unsupervised, so feedback is used to **prune** bad
training rows rather than relabel them:

| `was_legitimate` | Action |
|---|---|
| `true`, model flagged | Keep the row (reinforces that the feature vector is fine) |
| `false`, model allowed | Inject 3× copies with a slight perturbation to push the detector's boundary |

This preserves the unsupervised contract while nudging the model
toward reviewer intent. Over time this produces a detector whose
false-positive rate trends downward because repeatedly-flagged
legitimate patterns are reinforced as "inlier" examples.

## Metrics

The nightly job exposes the following Prometheus gauges (scraped via
the FastAPI service's `/metrics` endpoint):

| Metric | Meaning |
|---|---|
| `risk_model_training_rows` | Total rows used for the last fit |
| `risk_model_anomaly_rate` | Proportion of rows flagged anomalous |
| `risk_model_feedback_rows` | New feedback events ingested this run |
| `risk_model_last_trained_ts` | Unix timestamp of the last successful training |
