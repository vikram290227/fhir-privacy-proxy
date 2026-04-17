"""
Nightly retraining job for the Isolation Forest anomaly detector.

Reads the original training CSV plus the reviewer feedback NDJSON
produced by `risk_service.py#/feedback`, merges them per the weighting
rules in `feedback_loop.md`, retrains the pipeline, and atomically
swaps the joblib so the FastAPI service's mtime watcher can hot-reload
without downtime.

Usage (typically from cron / a GitHub Action):

    python ml/retrain_nightly.py \
        --input ml/data/access_logs.csv \
        --feedback ml/data/feedback.ndjson \
        --model ml/models/iforest.joblib

The script is designed to be idempotent — feedback rows are kept in
the append-only NDJSON and are merged on every run; no file is mutated
except the active model. If there are no feedback rows yet it still
runs a training cycle (so the scheduled job stays meaningful even in
the quiet periods between verdicts).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

try:
    import joblib
    import numpy as np
    import pandas as pd
except ImportError as e:  # pragma: no cover
    raise SystemExit(
        "Retraining requires scikit-learn, pandas, numpy, joblib. "
        "Install with: pip install -r ml/requirements.txt"
    ) from e

# train_isolation_forest lives next to this file; allow `python ml/retrain_nightly.py`
# and `python -m ml.retrain_nightly` both to find it.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from schema import FEATURE_COLUMNS  # noqa: E402
from train_isolation_forest import build_pipeline, normalize_score  # noqa: E402


# ---------------------------------------------------------------------
# Feedback ingestion
# ---------------------------------------------------------------------

# Numeric columns that receive Gaussian perturbation on false-negative
# injections. Booleans (break_glass, patient_sensitive, department_match)
# are left untouched because jittering them flips their meaning, and
# role/action/resource_type are categorical.
_PERTURB_COLUMNS = ["hour", "day_of_week"]

# Per-column stddev for the jitter. Kept small so the injected rows
# still resemble the reviewer-flagged pattern; large enough that each
# copy lands in a different leaf of the Isolation Forest.
_PERTURB_SCALE = {
    "hour": 0.5,
    "day_of_week": 0.5,
}

# Number of perturbed copies for each false-negative feedback row —
# matches the 3× described in feedback_loop.md.
_FALSE_NEG_COPIES = 3


def _load_feedback(path: str | os.PathLike) -> list[dict]:
    """Read the NDJSON feedback log, returning one dict per line.

    A missing file is treated as "no feedback yet" — this keeps the
    nightly job safe to run on a fresh install where no reviewer has
    POSTed a verdict yet.
    """
    p = Path(path)
    if not p.exists():
        return []
    rows: list[dict] = []
    with p.open() as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as err:
                # Skip but warn — a single bad line shouldn't fail the
                # whole retrain. Operators can diff the ndjson to find
                # the corrupt row at leisure.
                print(f"retrain: feedback line {i} invalid JSON, skipping: {err}",
                      file=sys.stderr)
    return rows


def _feedback_to_rows(feedback: list[dict], rng: random.Random) -> pd.DataFrame:
    """Convert feedback records into training-set rows.

    Follows the rules in feedback_loop.md:
      * was_legitimate=True — the model flagged but the reviewer says
        it's fine. Inject one unperturbed copy so the detector sees
        this vector as an inlier.
      * was_legitimate=False — the model allowed but it was actually
        anomalous. Inject 3 slightly-perturbed copies so the boundary
        bends toward reviewer intent without single-point overfit.
    """
    if not feedback:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    out: list[dict] = []
    for rec in feedback:
        base = _feedback_row(rec)
        if base is None:
            continue
        if rec.get("was_legitimate", False):
            out.append(base)
        else:
            for _ in range(_FALSE_NEG_COPIES):
                out.append(_perturb(base, rng))
    return pd.DataFrame(out, columns=FEATURE_COLUMNS)


def _feedback_row(rec: dict) -> dict | None:
    """Project a feedback record onto the training feature schema.

    Returns None if a required field is missing; the caller skips the
    record so one bad NDJSON line can't corrupt the whole run.
    """
    try:
        return {
            "hour": int(rec["hour"]),
            "day_of_week": int(rec["day_of_week"]),
            "break_glass": int(bool(rec.get("break_glass", False))),
            "patient_sensitive": int(bool(rec.get("patient_sensitive", False))),
            "department_match": int(bool(rec.get("department_match", True))),
            "role": str(rec["role"]),
            "action": str(rec["action"]),
            "resource_type": str(rec["resource_type"]),
        }
    except (KeyError, TypeError, ValueError):
        return None


def _perturb(row: dict, rng: random.Random) -> dict:
    """Return a copy of row with small Gaussian noise on numeric fields."""
    out = dict(row)
    for col in _PERTURB_COLUMNS:
        if col not in out:
            continue
        scale = _PERTURB_SCALE.get(col, 0.5)
        noisy = float(out[col]) + rng.gauss(0.0, scale)
        # Clamp hour/day_of_week back into their legal ranges.
        if col == "hour":
            noisy = max(0, min(23, round(noisy)))
        elif col == "day_of_week":
            noisy = max(0, min(6, round(noisy)))
        out[col] = int(noisy)
    return out


# ---------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------

def _coerce_bools(df: pd.DataFrame) -> pd.DataFrame:
    """IsolationForest doesn't accept raw bool columns — cast to int.

    Mirrors the treatment in train_isolation_forest.main() so the two
    code paths produce interchangeable models.
    """
    for col in ("break_glass", "patient_sensitive", "department_match"):
        if col in df.columns:
            df[col] = df[col].astype(int)
    return df


def _atomic_write(pipe, target: str | os.PathLike) -> None:
    """Write the joblib to a `.next` sibling, then rename into place.

    os.replace is atomic on POSIX so readers (the FastAPI mtime
    watcher) always see either the old model or the new one, never a
    half-written file.
    """
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.with_suffix(target.suffix + ".next")
    joblib.dump(pipe, staging)
    os.replace(staging, target)


def retrain(
    input_csv: str | os.PathLike,
    feedback_ndjson: str | os.PathLike,
    model_path: str | os.PathLike,
    *,
    seed: int = 42,
) -> dict:
    """Run one retraining cycle and return a summary dict.

    The summary mirrors the Prometheus gauges exported by the FastAPI
    service (training_rows, feedback_rows, anomaly_rate,
    last_trained_ts) so a CI / cron caller can assert on it directly.
    """
    rng = random.Random(seed)

    base_df = pd.read_csv(input_csv)
    base_df = _coerce_bools(base_df)[FEATURE_COLUMNS].copy()

    feedback = _load_feedback(feedback_ndjson)
    fb_df = _feedback_to_rows(feedback, rng)

    if not fb_df.empty:
        fb_df = _coerce_bools(fb_df)[FEATURE_COLUMNS].copy()
        combined = pd.concat([base_df, fb_df], ignore_index=True)
    else:
        combined = base_df

    pipe = build_pipeline()
    pipe.fit(combined)

    # Anomaly rate on the *training* set — this is what
    # risk_model_anomaly_rate tracks. It's a useful drift signal even
    # though the underlying contamination parameter is fixed at 0.02.
    raw = pipe.named_steps["iforest"].decision_function(
        pipe.named_steps["prep"].transform(combined)
    )
    scores = np.array([normalize_score(float(s)) for s in raw])
    anomaly_rate = float((scores >= 0.6).mean())

    _atomic_write(pipe, model_path)
    trained_ts = int(time.time())

    summary = {
        "training_rows": int(len(combined)),
        "feedback_rows": int(len(feedback)),
        "anomaly_rate": round(anomaly_rate, 4),
        "last_trained_ts": trained_ts,
        "model_path": str(model_path),
    }

    # Sidecar summary. The FastAPI service reads this on hot-reload
    # and publishes the values as Prometheus gauges — keeping the
    # summary next to the joblib means promoting a new model is a
    # single atomic filesystem observation.
    meta_path = Path(str(model_path) + ".meta.json")
    meta_staging = meta_path.with_suffix(meta_path.suffix + ".next")
    with meta_staging.open("w") as f:
        json.dump({k: v for k, v in summary.items() if k != "model_path"}, f)
    os.replace(meta_staging, meta_path)

    return summary


def _format_summary(s: dict) -> str:
    return (
        f"rows trained:       {s['training_rows']}\n"
        f"feedback ingested:  {s['feedback_rows']}\n"
        f"anomaly rate:       {s['anomaly_rate']:.4f}\n"
        f"model path:         {s['model_path']}\n"
        f"last trained (unix): {s['last_trained_ts']}"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="ml/data/access_logs.csv",
                    help="Original training CSV")
    ap.add_argument("--feedback", default="ml/data/feedback.ndjson",
                    help="Reviewer verdicts written by /feedback")
    ap.add_argument("--model", default="ml/models/iforest.joblib",
                    help="Active model file (replaced atomically)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    summary = retrain(args.input, args.feedback, args.model, seed=args.seed)
    print(_format_summary(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
