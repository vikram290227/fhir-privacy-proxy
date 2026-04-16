"""Pytest coverage for ml/retrain_nightly.py.

The tests don't pull any real data from disk — they synthesise a
small CSV + NDJSON pair in a tmp_path, run one retrain cycle, and
then load the produced joblib to confirm the new model actually
predicts on fresh feature vectors. This is the invariant that matters
for production: the retrain loop must always leave a servable model
behind, even when the feedback file is empty or partially corrupt.
"""

from __future__ import annotations

import csv
import json
import os
import random
from pathlib import Path

import joblib
import pandas as pd
import pytest

import retrain_nightly
from schema import FEATURE_COLUMNS


# ---------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------


def _normal_row(hour: int = 10, day: int = 2) -> dict:
    """One 'inlier-shaped' row: business hours, in-dept, no break-glass."""
    return {
        "user_id": "nurse1",
        "role": "nurse",
        "department": "cardiology",
        "patient_id": "p1",
        "resource_type": "Patient",
        "action": "read",
        "hour": hour,
        "day_of_week": day,
        "break_glass": False,
        "patient_sensitive": False,
        "department_match": True,
        "tenant_id": "hospital-a",
        "decision": "allow",
    }


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def _write_ndjson(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _synth_training_set(n: int = 400, seed: int = 0) -> list[dict]:
    """IsolationForest refuses to fit on a degenerate single-mode set,
    so sprinkle a small amount of variation across the feature space."""
    rng = random.Random(seed)
    rows = []
    for _ in range(n):
        r = _normal_row(
            hour=rng.randint(7, 19),
            day=rng.randint(1, 5),
        )
        r["role"] = rng.choice(["nurse", "doctor"])
        r["resource_type"] = rng.choice(["Patient", "Observation"])
        r["action"] = "read" if rng.random() < 0.9 else "write"
        rows.append(r)
    return rows


@pytest.fixture
def env(tmp_path: Path) -> dict:
    """Everything a retrain needs in a sandboxed tmp tree."""
    csv_path = tmp_path / "data" / "access_logs.csv"
    feedback_path = tmp_path / "data" / "feedback.ndjson"
    model_path = tmp_path / "models" / "iforest.joblib"
    _write_csv(csv_path, _synth_training_set())
    return {
        "csv": csv_path,
        "feedback": feedback_path,
        "model": model_path,
    }


# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------


def test_retrain_without_feedback_produces_servable_model(env):
    """Empty feedback file (or missing) must still produce a model."""
    summary = retrain_nightly.retrain(env["csv"], env["feedback"], env["model"])
    assert summary["feedback_rows"] == 0
    assert summary["training_rows"] == 400
    assert env["model"].exists()

    pipe = joblib.load(env["model"])
    # The pipeline must accept fresh rows and yield a finite decision
    # score — the smoke test the FastAPI /score endpoint effectively
    # runs on every request.
    row = pd.DataFrame(
        [{
            "hour": 3, "day_of_week": 6,
            "break_glass": 0, "patient_sensitive": 1, "department_match": 0,
            "role": "nurse", "action": "write", "resource_type": "MedicationRequest",
        }],
        columns=FEATURE_COLUMNS,
    )
    transformed = pipe.named_steps["prep"].transform(row)
    score = pipe.named_steps["iforest"].decision_function(transformed)
    assert score.shape == (1,)
    # decision_function always returns a finite float for valid input.
    assert score[0] == score[0]  # not NaN


def test_retrain_injects_three_copies_for_false_negative(env):
    """was_legitimate=False expands to 3 training rows per feedback."""
    feedback = [
        {
            # anomaly-shaped: night-time nurse write on sensitive patient
            "user_id": "nurse9", "role": "nurse", "resource_type": "Observation",
            "action": "write", "hour": 2, "day_of_week": 6,
            "department_match": False, "break_glass": False,
            "patient_sensitive": True,
            "was_legitimate": False,
            "reviewer": "secops@example.com",
        }
    ]
    _write_ndjson(env["feedback"], feedback)
    summary = retrain_nightly.retrain(env["csv"], env["feedback"], env["model"])

    # 400 base + 3 injected = 403 rows used for the fit.
    assert summary["training_rows"] == 403
    # feedback_rows counts records read (not the post-expansion count)
    # so operators can tell "one false negative expanded" apart from
    # "three separate false negatives".
    assert summary["feedback_rows"] == 1


def test_retrain_keeps_legitimate_feedback_unperturbed(env):
    """was_legitimate=True adds exactly one row (no perturbation)."""
    feedback = [
        {
            "user_id": "nurse2", "role": "nurse", "resource_type": "Patient",
            "action": "read", "hour": 10, "day_of_week": 2,
            "department_match": True, "break_glass": False,
            "patient_sensitive": False,
            "was_legitimate": True,
            "reviewer": "audit@example.com",
        }
    ]
    _write_ndjson(env["feedback"], feedback)
    summary = retrain_nightly.retrain(env["csv"], env["feedback"], env["model"])
    assert summary["training_rows"] == 401
    assert summary["feedback_rows"] == 1


def test_retrain_ignores_corrupt_ndjson_lines(env):
    """A single malformed line in feedback.ndjson must not kill the run."""
    good = {
        "user_id": "nurse2", "role": "nurse", "resource_type": "Patient",
        "action": "read", "hour": 10, "day_of_week": 2,
        "department_match": True, "break_glass": False,
        "patient_sensitive": False,
        "was_legitimate": True,
        "reviewer": "audit@example.com",
    }
    env["feedback"].parent.mkdir(parents=True, exist_ok=True)
    with env["feedback"].open("w") as f:
        f.write(json.dumps(good) + "\n")
        f.write("{not valid json\n")
        f.write(json.dumps(good) + "\n")

    summary = retrain_nightly.retrain(env["csv"], env["feedback"], env["model"])
    # The two good lines count, the junk is skipped; each is legitimate
    # so each expands to 1 row.
    assert summary["feedback_rows"] == 2
    assert summary["training_rows"] == 402


def test_retrain_writes_meta_sidecar(env):
    """The sidecar JSON is what the FastAPI /metrics endpoint consumes."""
    retrain_nightly.retrain(env["csv"], env["feedback"], env["model"])
    meta_path = env["model"].parent / (env["model"].name + ".meta.json")
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text())
    # All four gauges are populated.
    for key in ("training_rows", "feedback_rows", "anomaly_rate",
                "last_trained_ts"):
        assert key in meta


def test_retrain_atomic_rename(env):
    """No transient .next file should remain after a successful run."""
    retrain_nightly.retrain(env["csv"], env["feedback"], env["model"])
    leftover = env["model"].parent / (env["model"].name + ".next")
    assert not leftover.exists()


def test_main_cli_smoke(env, capsys):
    """The CLI path prints the summary keys that operators grep for."""
    rc = retrain_nightly.main([
        "--input", str(env["csv"]),
        "--feedback", str(env["feedback"]),
        "--model", str(env["model"]),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "rows trained" in out
    assert "feedback ingested" in out
    assert "anomaly rate" in out
