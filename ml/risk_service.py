"""
FastAPI risk-scoring service consumed by the Go proxy.

The service loads the trained Isolation Forest pipeline (joblib) at
startup, exposes:
    POST /score       -> returns {score, label, explanation}
    POST /feedback    -> records supervised feedback for retraining
    GET  /health      -> liveness probe

Start locally:
    uvicorn ml.risk_service:app --host 0.0.0.0 --port 8000 --reload

Environment:
    MODEL_PATH  = ml/models/iforest.joblib   (default)
    FEEDBACK_LOG = ml/data/feedback.ndjson   (append-only NDJSON log)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

try:
    import joblib
    import numpy as np
    import pandas as pd
    from fastapi import FastAPI
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

app = FastAPI(title="FHIR Privacy Risk Scoring", version="1.0.0")
_model = None
_shap_explainer = None


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


def _load_model():
    global _model, _shap_explainer
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            # Allow the service to boot without a trained model —
            # /score will return neutral responses so the proxy never
            # fails closed during development.
            return None
        _model = joblib.load(MODEL_PATH)
        if _HAS_SHAP:
            try:
                iforest = _model.named_steps["iforest"]
                _shap_explainer = shap.TreeExplainer(iforest)
            except Exception:
                _shap_explainer = None
    return _model


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


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "model_loaded": str(_load_model() is not None),
        "shap": str(_HAS_SHAP),
    }


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
    except Exception:
        return ScoreResponse(score=0.0, label="normal", explanation={})

    score_val = _normalize(raw)
    label = _label_for(score_val)

    explanation: dict[str, float] = {}
    if _shap_explainer is not None:
        try:
            transformed = model.named_steps["prep"].transform(x)
            shap_values = _shap_explainer.shap_values(transformed)
            feature_names = _feature_names(model)
            attr = np.array(shap_values).flatten()
            # Keep the top 5 absolute contributions to reduce payload size.
            order = np.argsort(-np.abs(attr))[:5]
            for idx in order:
                explanation[feature_names[idx]] = round(float(attr[idx]), 4)
        except Exception:
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
