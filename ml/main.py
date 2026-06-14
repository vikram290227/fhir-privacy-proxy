"""
FHIR Risk Scoring Service — FastAPI entry point.

Phase 1: Rule-based baseline scorer (no model required).
Phase 2: Loads model.json (XGBoost) at startup when present.

Start locally:
    uvicorn ml.main:app --host 0.0.0.0 --port 8000 --reload

Environment:
    MODEL_PATH   = model.json  (default, optional)
"""
from __future__ import annotations

import logging
import os
from typing import List

logger = logging.getLogger("risk-service")

try:
    from fastapi import FastAPI
    from pydantic import BaseModel
    import numpy as np
except ImportError as e:  # pragma: no cover
    raise SystemExit(
        "Run `pip install -r ml/requirements.txt` before starting the service."
    ) from e

MODEL_PATH = os.getenv("MODEL_PATH", "model.json")
model = None

app = FastAPI(title="FHIR Risk Scoring Service", version="0.1.0")


class AccessRequest(BaseModel):
    subject_id: str
    tenant_id: str
    department: str
    role: str
    resource_type: str
    resource_path: str
    action: str
    hour_of_day: int
    day_of_week: int
    accesses_last_hour: int
    accesses_today: int
    is_typical_department: bool
    has_care_team_relation: bool
    is_break_glass: bool


class RiskResponse(BaseModel):
    risk_score: float
    confidence: float
    reason: str
    top_factors: List[str]


@app.on_event("startup")
def load_model() -> None:
    global model
    if os.path.exists(MODEL_PATH):
        try:
            import xgboost as xgb
            model = xgb.XGBClassifier()
            model.load_model(MODEL_PATH)
            logger.info("XGBoost model loaded from %s", MODEL_PATH)
        except Exception as exc:
            logger.warning("failed to load model from %s: %s", MODEL_PATH, exc)
            model = None
    else:
        logger.info("No model file found — using rule-based scorer")


@app.get("/health")
def health() -> dict:
    model_name = "xgboost" if model is not None else "rule-based-baseline"
    return {"status": "ok", "model": model_name}


@app.post("/score", response_model=RiskResponse)
def score_access(req: AccessRequest) -> RiskResponse:
    """
    Phase 1: Rule-based scoring (no ML model yet).
    Returns deterministic risk scores based on known risk factors.
    Phase 2: Uses trained XGBoost model when model.json is present.
    """
    if model is not None:
        return _xgboost_score(req)
    return _rule_based_score(req)


def _rule_based_score(req: AccessRequest) -> RiskResponse:
    risk = 0.0
    factors: List[str] = []

    if req.hour_of_day >= 22 or req.hour_of_day <= 5:
        risk += 0.25
        factors.append("After-hours access")

    if req.accesses_last_hour > 50:
        risk += 0.30
        factors.append(f"High volume: {req.accesses_last_hour} accesses in last hour")
    elif req.accesses_last_hour > 20:
        risk += 0.15
        factors.append(f"Elevated volume: {req.accesses_last_hour} accesses in last hour")

    if not req.is_typical_department and not req.has_care_team_relation:
        risk += 0.25
        factors.append("Cross-department access without care team relation")

    if req.is_break_glass:
        factors.append("Break-glass override active")

    if req.day_of_week >= 5 and req.accesses_today > 30:
        risk += 0.10
        factors.append("High weekend access volume")

    risk = min(risk, 1.0)
    confidence = 0.70 if factors else 0.90

    return RiskResponse(
        risk_score=round(risk, 3),
        confidence=confidence,
        reason="rule-based" if risk < 0.3 else "elevated-risk-pattern",
        top_factors=factors[:3],
    )


def _xgboost_score(req: AccessRequest) -> RiskResponse:
    features = np.array([[
        req.hour_of_day,
        req.day_of_week,
        req.accesses_last_hour,
        req.accesses_today,
        int(req.is_typical_department),
        int(req.has_care_team_relation),
        int(req.is_break_glass),
    ]])
    risk = float(model.predict_proba(features)[0][1])
    return RiskResponse(
        risk_score=round(risk, 3),
        confidence=0.85,
        reason="xgboost-model",
        top_factors=[],
    )
