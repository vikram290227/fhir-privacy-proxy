"""
FastAPI risk-scoring service consumed by the Go proxy.

The service loads the trained Isolation Forest pipeline (joblib) at
startup, exposes:
    POST /score       -> returns {score, label, explanation}
    POST /feedback    -> records supervised feedback for retraining
    GET  /health      -> liveness probe
    GET  /metrics     -> Prometheus gauges describing the live model

Start locally:
    uvicorn ml.risk_service:app --host 0.0.0.0 --port 8000 --reload

Environment:
    MODEL_PATH       = ml/models/iforest.joblib   (default)
    FEEDBACK_LOG     = ml/data/feedback.ndjson    (append-only NDJSON log)
    MODEL_POLL_SECS  = 30                         (hot-reload poll interval)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import joblib
    import numpy as np
    import pandas as pd
    from fastapi import FastAPI, Response
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Gauge,
        generate_latest,
    )
    from pydantic import BaseModel, Field
except ImportError as e:  # pragma: no cover
    raise SystemExit(
        "Run `pip install -r ml/requirements.txt` before starting the service."
    ) from e

try:
    import shap  # type: ignore
    _HAS_SHAP = True
except ImportError:  # pragma: no cover
    _HAS_SHAP = False


MODEL_PATH = os.environ.get("MODEL_PATH", "ml/models/iforest.joblib")
FEEDBACK_LOG = os.environ.get("FEEDBACK_LOG", "ml/data/feedback.ndjson")
MODEL_POLL_SECS = float(os.environ.get("MODEL_POLL_SECS", "30"))

app = FastAPI(title="FHIR Privacy Risk Scoring", version="1.0.0")
_model = None
_shap_explainer = None
_shap_healthy: bool = False
_model_lock = threading.RLock()
_model_mtime: float = 0.0

# A private registry keeps the service's metrics isolated from the
# process-wide default registry used by third-party libraries, so
# `/metrics` emits only the risk-model gauges described in
# feedback_loop.md. The gauges are driven by retrain_nightly.py
# (training_rows, anomaly_rate, feedback_rows, last_trained_ts) and
# updated from the model's own metadata block when it is loaded.
_REGISTRY = CollectorRegistry()
TRAINING_ROWS_GAUGE = Gauge(
    "risk_model_training_rows",
    "Total rows used for the last successful fit (incl. feedback injections)",
    registry=_REGISTRY,
)
ANOMALY_RATE_GAUGE = Gauge(
    "risk_model_anomaly_rate",
    "Proportion of training rows scored at or above the 'suspicious' threshold (0.6)",
    registry=_REGISTRY,
)
FEEDBACK_ROWS_GAUGE = Gauge(
    "risk_model_feedback_rows",
    "Number of reviewer feedback events ingested by the last retrain run",
    registry=_REGISTRY,
)
LAST_TRAINED_GAUGE = Gauge(
    "risk_model_last_trained_ts",
    "Unix timestamp of the last successful retrain",
    registry=_REGISTRY,
)


class ScoreRequest(BaseModel):
    user_id: str
    role: str
    department: str
    patient_id: Optional[str] = ""
    resource_type: str
    action: str
    hour: int = Field(..., ge=0, le=23)
    day_of_week: int = Field(..., ge=0, le=6)
    break_glass: bool = False
    patient_sensitive: bool = False
    department_match: bool = True


class ScoreResponse(BaseModel):
    score: float
    label: str
    explanation: dict[str, float] = {}


class FeedbackRequest(BaseModel):
    user_id: str
    role: str
    resource_type: str
    action: str
    hour: int
    day_of_week: int
    department_match: bool
    break_glass: bool
    patient_sensitive: bool
    was_legitimate: bool
    reviewer: str


_SHAP_PROBE_ROW = {
    "hour": 10,
    "day_of_week": 2,
    "break_glass": 0,
    "patient_sensitive": 0,
    "department_match": 1,
    "role": "nurse",
    "action": "read",
    "resource_type": "Patient",
}


def _build_shap_explainer(pipeline):
    """Construct a TreeExplainer for the iforest stage and run it once
    against a synthetic row to verify the full pipeline works.

    Returns `(explainer, healthy)`. Any failure is logged with the
    exception type so operators can see exactly why SHAP was disabled
    (sklearn version skew, missing optional numpy ABI, model-shape
    mismatch, etc.) rather than silently degrading to heuristics.
    """
    if not _HAS_SHAP:
        logger.info("shap not installed; falling back to heuristic explanations")
        return None, False
    try:
        iforest = pipeline.named_steps["iforest"]
        explainer = shap.TreeExplainer(iforest)
    except Exception as e:
        logger.warning(
            "shap explainer construction failed (%s: %s); "
            "falling back to heuristic explanations",
            type(e).__name__, e,
        )
        return None, False

    try:
        probe = pd.DataFrame([_SHAP_PROBE_ROW])
        transformed = pipeline.named_steps["prep"].transform(probe)
        values = explainer.shap_values(transformed)
        attr = np.array(values).flatten()
        if attr.size == 0:
            logger.warning(
                "shap probe returned an empty attribution vector; "
                "falling back to heuristic explanations",
            )
            return None, False
    except Exception as e:
        logger.warning(
            "shap probe failed (%s: %s); "
            "falling back to heuristic explanations",
            type(e).__name__, e,
        )
        return None, False

    logger.info("shap probe succeeded; SHAP explanations enabled")
    return explainer, True


def _load_model():
    """Return the live pipeline, loading-or-reloading from disk if the
    joblib mtime has advanced since we last looked.

    First call: fault-in from disk (or return None if no model has
    been trained yet — keeps the service able to boot during local
    dev). Subsequent calls: re-read only when mtime has changed, so
    /score stays on the hot path. All reads are guarded by
    _model_lock so a concurrent background reload can't hand a
    partially-initialised model to a request.
    """
    global _model, _shap_explainer, _shap_healthy, _model_mtime
    try:
        mtime = os.path.getmtime(MODEL_PATH)
    except OSError:
        # File absent on cold boot is expected; don't log per poll.
        return _model

    with _model_lock:
        if _model is not None and mtime == _model_mtime:
            return _model
        try:
            pipeline = joblib.load(MODEL_PATH)
        except Exception as e:
            logger.error(
                "failed to load model from %s (%s: %s); keeping previous model",
                MODEL_PATH, type(e).__name__, e,
            )
            return _model
        _model = pipeline
        _model_mtime = mtime
        _shap_explainer, _shap_healthy = _build_shap_explainer(pipeline)
        _refresh_metrics_from_model()
        logger.info(
            "loaded model from %s (shap_healthy=%s)",
            MODEL_PATH, _shap_healthy,
        )
    return _model


def _refresh_metrics_from_model() -> None:
    """Pull the retrainer's sidecar summary (if present) into Prometheus.

    retrain_nightly.py writes `<model>.meta.json` next to the active
    joblib so the FastAPI service can reflect training_rows /
    anomaly_rate / feedback_rows without recomputing them. If the
    sidecar is missing we only update the last_trained timestamp from
    the joblib mtime so the "last seen a model" signal is still
    accurate.
    """
    meta_path = MODEL_PATH + ".meta.json"
    try:
        with open(meta_path) as f:
            meta = json.load(f)
    except (OSError, json.JSONDecodeError):
        meta = {}

    if "training_rows" in meta:
        TRAINING_ROWS_GAUGE.set(float(meta["training_rows"]))
    if "anomaly_rate" in meta:
        ANOMALY_RATE_GAUGE.set(float(meta["anomaly_rate"]))
    if "feedback_rows" in meta:
        FEEDBACK_ROWS_GAUGE.set(float(meta["feedback_rows"]))
    if "last_trained_ts" in meta:
        LAST_TRAINED_GAUGE.set(float(meta["last_trained_ts"]))
    else:
        LAST_TRAINED_GAUGE.set(_model_mtime)


# ---------------------------------------------------------------------
# Hot-reload watcher
# ---------------------------------------------------------------------

_watcher_started = False
_watcher_lock = threading.Lock()


def _watch_model_file(poll_secs: float) -> None:
    """Background loop that triggers _load_model() on an interval.

    The reloader itself is the single source of truth for the mtime
    check, so this thread just pokes it. Using a thread instead of
    inotify keeps the code portable (macOS dev, Linux prod, CI
    containers) with a small constant cost of one filesystem stat
    every poll_secs.
    """
    while True:
        try:
            _load_model()
        except Exception:  # pragma: no cover - defensive
            pass
        time.sleep(poll_secs)


def _ensure_watcher_started() -> None:
    global _watcher_started
    if _watcher_started or MODEL_POLL_SECS <= 0:
        return
    with _watcher_lock:
        if _watcher_started:
            return
        t = threading.Thread(
            target=_watch_model_file,
            args=(MODEL_POLL_SECS,),
            name="risk-model-watcher",
            daemon=True,
        )
        t.start()
        _watcher_started = True


def _normalize(raw: float) -> float:
    """Rescale IsolationForest decision_function output to [0, 1]."""
    clipped = max(-0.25, min(0.25, raw))
    return round(0.5 - (clipped * 2), 4)


def _label_for(score: float) -> str:
    if score >= 0.85:
        return "anomalous"
    if score >= 0.6:
        return "suspicious"
    return "normal"


def _row_from_request(req: ScoreRequest) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "hour": req.hour,
                "day_of_week": req.day_of_week,
                "break_glass": int(req.break_glass),
                "patient_sensitive": int(req.patient_sensitive),
                "department_match": int(req.department_match),
                "role": req.role,
                "action": req.action,
                "resource_type": req.resource_type,
            }
        ]
    )


@app.on_event("startup")
def _startup() -> None:  # pragma: no cover - exercised by uvicorn
    _load_model()
    _ensure_watcher_started()


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "model_loaded": str(_load_model() is not None),
        "shap_installed": str(_HAS_SHAP),
        "shap_healthy": str(_shap_healthy),
    }


@app.get("/metrics")
def metrics() -> Response:
    """Prometheus scrape endpoint.

    Always re-checks the joblib mtime before rendering — this means a
    freshly-retrained model is reflected in `risk_model_*` gauges the
    first time Prometheus scrapes us after the atomic rename, without
    waiting for the 30s background poll.
    """
    _load_model()
    return Response(generate_latest(_REGISTRY), media_type=CONTENT_TYPE_LATEST)


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest) -> ScoreResponse:
    model = _load_model()
    if model is None:
        return ScoreResponse(score=0.0, label="normal", explanation={})

    x = _row_from_request(req)
    try:
        raw = float(model.named_steps["iforest"].decision_function(
            model.named_steps["prep"].transform(x)
        )[0])
    except Exception as e:
        logger.warning(
            "score: IsolationForest.decision_function raised %s: %s; "
            "returning neutral response",
            type(e).__name__, e,
        )
        return ScoreResponse(score=0.0, label="normal", explanation={})

    score_val = _normalize(raw)
    label = _label_for(score_val)

    explanation: dict[str, float] = {}
    if _shap_healthy and _shap_explainer is not None:
        try:
            transformed = model.named_steps["prep"].transform(x)
            shap_values = _shap_explainer.shap_values(transformed)
            feature_names = _feature_names(model)
            attr = np.array(shap_values).flatten()
            # Keep the top 5 absolute contributions to reduce payload size.
            order = np.argsort(-np.abs(attr))[:5]
            for idx in order:
                explanation[feature_names[idx]] = round(float(attr[idx]), 4)
        except Exception as e:
            logger.warning(
                "score: SHAP explanation raised %s: %s; "
                "falling back to heuristic explanation",
                type(e).__name__, e,
            )
            explanation = {}

    # Heuristic fallback explanations keep the API useful even without SHAP.
    if not explanation:
        if req.hour < 6 or req.hour > 21:
            explanation["unusual_hour"] = 0.4
        if not req.department_match:
            explanation["department_mismatch"] = 0.35
        if req.patient_sensitive and not req.break_glass:
            explanation["sensitive_without_breakglass"] = 0.25
        if req.role == "nurse" and req.action == "write":
            explanation["nurse_write"] = 0.2

    return ScoreResponse(score=score_val, label=label, explanation=explanation)


@app.post("/feedback")
def feedback(req: FeedbackRequest) -> dict[str, str]:
    """
    Persist a supervised-feedback event so the nightly retrainer can
    reinforce or correct the model.
    """
    os.makedirs(os.path.dirname(FEEDBACK_LOG), exist_ok=True)
    record = req.model_dump()
    record["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(FEEDBACK_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")
    return {"status": "recorded"}


def _feature_names(pipeline) -> list[str]:
    prep = pipeline.named_steps["prep"]
    numeric = list(prep.transformers_[0][2])
    ohe = prep.transformers_[1][1]
    cat_cols = list(prep.transformers_[1][2])
    try:
        ohe_names = list(ohe.get_feature_names_out(cat_cols))
    except Exception:
        ohe_names = cat_cols
    return numeric + ohe_names
