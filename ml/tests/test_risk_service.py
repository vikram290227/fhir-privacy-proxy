"""Behavioural coverage for ml/risk_service.py.

These tests drive the FastAPI app through its real HTTP surface via
TestClient so validation, serialization, and the SHAP branch are all
exercised together. Each test pins the module-level MODEL_PATH /
FEEDBACK_LOG / watcher state in tmp_path so fixtures can't leak
across tests — the risk_service module is stateful (loaded pipeline,
mtime cache, `_shap_healthy` flag) and must be reset explicitly
before each scenario.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import risk_service


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _valid_request(**overrides: Any) -> dict:
    """A baseline /score payload that is a clean inlier for the
    synthetic trained model in conftest.py: business hours, in-dept,
    no break-glass, non-sensitive patient."""
    req = {
        "user_id": "nurse1",
        "role": "nurse",
        "department": "cardiology",
        "patient_id": "p1",
        "resource_type": "Patient",
        "action": "read",
        "hour": 10,
        "day_of_week": 2,
        "break_glass": False,
        "patient_sensitive": False,
        "department_match": True,
    }
    req.update(overrides)
    return req


def _reset_service_state() -> None:
    """Clear any cached model / SHAP state from a prior test so the
    next _load_model() call fault-ins from the freshly-patched path."""
    risk_service._model = None
    risk_service._shap_explainer = None
    risk_service._shap_healthy = False
    risk_service._model_mtime = 0.0
    # The watcher thread is a daemon process-global; once started it
    # would keep polling the (possibly stale) MODEL_PATH across tests.
    # Flipping this flag prevents _ensure_watcher_started() from
    # spawning a new one, and any previously-started one is harmless
    # because we're also zeroing MODEL_POLL_SECS.
    risk_service._watcher_started = True


@pytest.fixture
def service_with_model(monkeypatch, tiny_model: Path, tmp_path: Path):
    """risk_service configured to serve `tiny_model`, with feedback
    persisted inside tmp_path."""
    feedback_path = tmp_path / "data" / "feedback.ndjson"
    monkeypatch.setattr(risk_service, "MODEL_PATH", str(tiny_model))
    monkeypatch.setattr(risk_service, "FEEDBACK_LOG", str(feedback_path))
    monkeypatch.setattr(risk_service, "MODEL_POLL_SECS", 0)
    _reset_service_state()
    yield risk_service


@pytest.fixture
def service_no_model(monkeypatch, tmp_path: Path):
    """risk_service pointed at a path that does not exist — simulates
    a fresh deploy before the first retrain has landed a joblib."""
    missing = tmp_path / "models" / "never_trained.joblib"
    feedback_path = tmp_path / "data" / "feedback.ndjson"
    monkeypatch.setattr(risk_service, "MODEL_PATH", str(missing))
    monkeypatch.setattr(risk_service, "FEEDBACK_LOG", str(feedback_path))
    monkeypatch.setattr(risk_service, "MODEL_POLL_SECS", 0)
    _reset_service_state()
    yield risk_service


# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------


def test_score_returns_neutral_when_model_missing(service_no_model):
    """With no joblib on disk the service must still answer /score
    rather than 500. Neutral score + empty explanation lets the Go
    proxy fall through to role-based policy without widening
    masking."""
    client = TestClient(service_no_model.app)
    resp = client.post("/score", json=_valid_request())
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"score": 0.0, "label": "normal", "explanation": {}}


def test_score_returns_valid_response_with_trained_model(service_with_model):
    """Happy path: every field is well-typed and bounded, and the
    label matches the score's bucket."""
    client = TestClient(service_with_model.app)
    resp = client.post("/score", json=_valid_request())
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["score"], float)
    assert 0.0 <= body["score"] <= 1.0
    assert body["label"] in {"normal", "suspicious", "anomalous"}
    if body["score"] >= 0.85:
        assert body["label"] == "anomalous"
    elif body["score"] >= 0.6:
        assert body["label"] == "suspicious"
    else:
        assert body["label"] == "normal"
    assert isinstance(body["explanation"], dict)


def test_shap_explanation_contains_expected_feature_names(service_with_model):
    """When SHAP is healthy the explanation keys must come from the
    pipeline's actual feature namespace (numeric + one-hot encoded
    categorical), not the heuristic set — that's the whole point of
    returning model-attributable explanations to reviewers."""
    if not service_with_model._HAS_SHAP:
        pytest.skip("shap library not installed")

    client = TestClient(service_with_model.app)
    # Trigger _load_model by hitting any endpoint, so the SHAP probe
    # runs and _shap_healthy gets set before we read it.
    client.get("/health")
    assert service_with_model._shap_healthy, (
        "the synthetic trained model should pass the SHAP probe; "
        "if this fails the probe itself is broken"
    )

    # Anomaly-shaped input biases the decision function so the top
    # attributions aren't all zero.
    req = _valid_request(
        hour=2, day_of_week=6,
        department_match=False, patient_sensitive=True,
    )
    resp = client.post("/score", json=req)
    assert resp.status_code == 200
    explanation = resp.json()["explanation"]
    assert explanation, "SHAP path should produce a non-empty explanation"

    expected = set(
        service_with_model._feature_names(service_with_model._model)
    )
    actual = set(explanation.keys())
    assert actual.issubset(expected), (
        f"explanation keys {actual} are not a subset of the pipeline's "
        f"feature namespace {expected}"
    )
    # Top-5-by-|attribution| is the service's documented contract.
    assert len(actual) <= 5


@pytest.mark.parametrize("field,bad_value", [
    ("hour", -1),
    ("hour", 24),
    ("day_of_week", -1),
    ("day_of_week", 7),
])
def test_score_validates_input_bounds(service_with_model, field, bad_value):
    """Pydantic bounds on hour (0-23) and day_of_week (0-6) must
    produce 422 before the request ever touches the model — the Go
    proxy relies on this to reject malformed access-log entries."""
    client = TestClient(service_with_model.app)
    req = _valid_request(**{field: bad_value})
    resp = client.post("/score", json=req)
    assert resp.status_code == 422
    # Pydantic v2 surfaces the offending field in `loc`.
    detail = resp.json()["detail"][0]
    assert field in detail["loc"]


def test_feedback_persists_to_expected_path(service_with_model):
    """/feedback must append a single NDJSON line at FEEDBACK_LOG and
    stamp it with an ISO timestamp — retrain_nightly.py keys off
    exactly this format."""
    client = TestClient(service_with_model.app)
    payload = {
        "user_id": "nurse9",
        "role": "nurse",
        "resource_type": "Observation",
        "action": "write",
        "hour": 2,
        "day_of_week": 6,
        "department_match": False,
        "break_glass": False,
        "patient_sensitive": True,
        "was_legitimate": False,
        "reviewer": "secops@example.com",
    }
    resp = client.post("/feedback", json=payload)
    assert resp.status_code == 200
    assert resp.json() == {"status": "recorded"}

    feedback_path = Path(service_with_model.FEEDBACK_LOG)
    assert feedback_path.exists(), "feedback file should be created on first write"
    lines = feedback_path.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    for key, value in payload.items():
        assert record[key] == value
    assert "timestamp" in record and record["timestamp"].endswith("+00:00")
