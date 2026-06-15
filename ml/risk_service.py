"""
FastAPI risk-scoring service consumed by the Go proxy.

The service loads the trained ONNX model at startup via a module-level
ort.InferenceSession (thread-safe; no RLock required for concurrent inference).
Joblib is retained only for SHAP explanations, loaded lazily and separately.

Endpoints:
    POST /score       -> returns {score, label, explanation}
    POST /feedback    -> records supervised feedback for retraining
    GET  /health      -> liveness probe
    GET  /metrics     -> Prometheus gauges describing the live model

Start locally:
    uvicorn ml.risk_service:app --host 0.0.0.0 --port 8000 --reload

Environment:
    ONNX_MODEL_PATH  = ml/models/risk_model.onnx      (default)
    VOCAB_PATH       = ml/models/risk_model.vocab.json (default)
    MODEL_PATH       = ml/models/iforest.joblib        (SHAP only)
    FEEDBACK_LOG     = ml/data/feedback.ndjson         (append-only NDJSON)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import numpy as np
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
    import onnxruntime as ort
    _HAS_ORT = True
except ImportError:  # pragma: no cover
    _HAS_ORT = False
    logger.warning("onnxruntime not installed; /score will return neutral scores")

try:
    import joblib
    import shap  # type: ignore
    _HAS_SHAP = True
except ImportError:
    _HAS_SHAP = False


ONNX_MODEL_PATH = os.environ.get("ONNX_MODEL_PATH", "ml/models/risk_model.onnx")
VOCAB_PATH = os.environ.get("VOCAB_PATH", "ml/models/risk_model.vocab.json")
MODEL_PATH = os.environ.get("MODEL_PATH", "ml/models/iforest.joblib")
FEEDBACK_LOG = os.environ.get("FEEDBACK_LOG", "ml/data/feedback.ndjson")

app = FastAPI(title="FHIR Privacy Risk Scoring", version="1.0.0")

# Module-level session — ort.InferenceSession is thread-safe for concurrent
# inference; no RLock required.
_session: "ort.InferenceSession | None" = None
_vocab: dict[str, list[str]] = {}

# SHAP explainer loaded lazily from joblib pipeline (explanations only).
_shap_pipeline = None
_shap_explainer = None
_shap_healthy: bool = False

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


def _load_onnx_session() -> "ort.InferenceSession | None":
    if not _HAS_ORT:
        return None
    try:
        sess = ort.InferenceSession(ONNX_MODEL_PATH)
        logger.info("ONNX model loaded from %s", ONNX_MODEL_PATH)
        return sess
    except Exception as e:
        logger.warning(
            "ONNX model not available (%s: %s); /score returns neutral",
            type(e).__name__, e,
        )
        return None


def _load_vocab() -> dict[str, list[str]]:
    try:
        with open(VOCAB_PATH) as f:
            return json.load(f)
    except Exception as e:
        logger.warning(
            "vocab not available (%s: %s); OHE encoding disabled",
            type(e).__name__, e,
        )
        return {}


def _load_shap() -> None:
    global _shap_pipeline, _shap_explainer, _shap_healthy
    if not _HAS_SHAP:
        return
    try:
        pipeline = joblib.load(MODEL_PATH)
        explainer = shap.TreeExplainer(pipeline.named_steps["iforest"])
        _shap_pipeline = pipeline
        _shap_explainer = explainer
        _shap_healthy = True
        logger.info("SHAP explainer loaded from %s", MODEL_PATH)
    except Exception as e:
        logger.warning(
            "SHAP load failed (%s: %s); heuristic explanations only",
            type(e).__name__, e,
        )


def _build_feature_vector(req: ScoreRequest) -> "np.ndarray":
    """Build the float32 feature vector matching the ColumnTransformer output order.

    Numeric passthrough (indices 0-4): hour, day_of_week, break_glass,
      patient_sensitive, department_match
    OHE categorical (indices 5+): role, action, resource_type
      (category order from risk_model.vocab.json, written by export_onnx.py)
    """
    numeric = [
        float(req.hour),
        float(req.day_of_week),
        float(req.break_glass),
        float(req.patient_sensitive),
        float(req.department_match),
    ]

    def ohe(col: str, value: str) -> list[float]:
        return [1.0 if c == value else 0.0 for c in _vocab.get(col, [])]

    features = (
        numeric
        + ohe("role", req.role)
        + ohe("action", req.action)
        + ohe("resource_type", req.resource_type)
    )
    return np.array([features], dtype=np.float32)


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


def _refresh_metrics_from_meta() -> None:
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


@app.on_event("startup")
def _startup() -> None:  # pragma: no cover
    global _session, _vocab
    _session = _load_onnx_session()
    _vocab = _load_vocab()
    _load_shap()
    _refresh_metrics_from_meta()


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "onnx_loaded": str(_session is not None),
        "shap_healthy": str(_shap_healthy),
    }


@app.get("/metrics")
def metrics() -> Response:
    _refresh_metrics_from_meta()
    return Response(generate_latest(_REGISTRY), media_type=CONTENT_TYPE_LATEST)


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest) -> ScoreResponse:
    if _session is None or not _vocab:
        return ScoreResponse(score=0.0, label="normal", explanation={})

    try:
        x = _build_feature_vector(req)
        input_name = _session.get_inputs()[0].name
        raw_output = _session.run(None, {input_name: x})
        # skl2onnx IsolationForest output: [label(int64), scores(float)]
        raw = float(raw_output[1][0][0]) if len(raw_output) > 1 else 0.0
    except Exception as e:
        logger.warning(
            "ONNX inference failed (%s: %s); returning neutral",
            type(e).__name__, e,
        )
        return ScoreResponse(score=0.0, label="normal", explanation={})

    score_val = _normalize(raw)
    label = _label_for(score_val)

    explanation: dict[str, float] = {}
    if _shap_healthy and _shap_explainer is not None and _shap_pipeline is not None:
        try:
            import pandas as pd
            probe = pd.DataFrame([{
                "hour": req.hour,
                "day_of_week": req.day_of_week,
                "break_glass": int(req.break_glass),
                "patient_sensitive": int(req.patient_sensitive),
                "department_match": int(req.department_match),
                "role": req.role,
                "action": req.action,
                "resource_type": req.resource_type,
            }])
            prep = _shap_pipeline.named_steps["prep"]
            transformed = prep.transform(probe)
            shap_values = _shap_explainer.shap_values(transformed)
            numeric_cols = list(prep.transformers_[0][2])
            ohe_cols = list(prep.transformers_[1][1].get_feature_names_out(
                list(prep.transformers_[1][2])
            ))
            feature_names = numeric_cols + ohe_cols
            attr = np.array(shap_values).flatten()
            for idx in np.argsort(-np.abs(attr))[:5]:
                explanation[feature_names[idx]] = round(float(attr[idx]), 4)
        except Exception as e:
            logger.warning("SHAP explanation failed (%s: %s)", type(e).__name__, e)

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
    os.makedirs(os.path.dirname(FEEDBACK_LOG), exist_ok=True)
    record = req.model_dump()
    record["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(FEEDBACK_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")
    return {"status": "recorded"}
