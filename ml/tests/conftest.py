"""Shared pytest fixtures for the ml/ test suite.

The ml/ directory is not a package (no package-level __init__.py),
so pytest's default sys.path doesn't find retrain_nightly, schema,
or risk_service unless we add the parent explicitly.

`tiny_model` trains a fresh IsolationForest pipeline in a tmp_path
so risk_service tests don't depend on a prebuilt joblib in the repo.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

_ML_DIR = Path(__file__).resolve().parent.parent
if str(_ML_DIR) not in sys.path:
    sys.path.insert(0, str(_ML_DIR))

import joblib
import pandas as pd
import pytest

from schema import FEATURE_COLUMNS
from train_isolation_forest import build_pipeline


def _synth_rows(n: int = 300, seed: int = 0) -> list[dict]:
    """IsolationForest refuses to fit on a degenerate single-mode
    dataset, so sprinkle variation across hour / day / role / action
    / resource_type. 300 rows is enough for both fit + SHAP probe.
    """
    rng = random.Random(seed)
    rows = []
    for _ in range(n):
        rows.append({
            "hour": rng.randint(7, 19),
            "day_of_week": rng.randint(1, 5),
            "break_glass": 0,
            "patient_sensitive": 0,
            "department_match": 1,
            "role": rng.choice(["nurse", "doctor"]),
            "action": "read" if rng.random() < 0.9 else "write",
            "resource_type": rng.choice(["Patient", "Observation"]),
        })
    return rows


@pytest.fixture
def tiny_model(tmp_path: Path) -> Path:
    """Train a small IsolationForest pipeline and persist it.

    Returns the joblib path. Fresh per-test so monkeypatched state in
    risk_service can't leak between tests.
    """
    model_path = tmp_path / "models" / "iforest.joblib"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(_synth_rows())
    pipe = build_pipeline()
    pipe.fit(df[FEATURE_COLUMNS])
    joblib.dump(pipe, model_path)
    return model_path
