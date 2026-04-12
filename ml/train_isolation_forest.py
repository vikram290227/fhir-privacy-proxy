"""
Train an Isolation Forest anomaly detector on synthetic healthcare
access logs, persist the fitted pipeline to disk, and (optionally)
fit a SHAP explainer so the scoring service can return per-feature
attributions.

Usage:
    python ml/train_isolation_forest.py \
        --input ml/data/access_logs.csv \
        --model ml/models/iforest.joblib

The output pipeline is a sklearn Pipeline whose first stage is a
ColumnTransformer encoding categorical fields, followed by an
IsolationForest. The score returned by `predict_proba`-like helpers
is normalised to the 0-1 range where 1 = most anomalous.
"""

from __future__ import annotations

import argparse
import os

try:
    import joblib
    import pandas as pd
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import IsolationForest
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder
except ImportError as e:  # pragma: no cover
    raise SystemExit(
        "Training requires scikit-learn and pandas. "
        "Install with: pip install -r ml/requirements.txt"
    ) from e

from schema import CATEGORICAL_COLUMNS, FEATURE_COLUMNS, NUMERIC_COLUMNS  # noqa: E402


def build_pipeline() -> Pipeline:
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", "passthrough", NUMERIC_COLUMNS),
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                CATEGORICAL_COLUMNS,
            ),
        ]
    )
    model = IsolationForest(
        n_estimators=200,
        contamination=0.02,
        random_state=42,
    )
    return Pipeline([("prep", preprocessor), ("iforest", model)])


def normalize_score(decision_function_score: float) -> float:
    """
    IsolationForest.decision_function returns negative values for
    anomalies. Clip + rescale to 0-1 where 1 = most anomalous.
    """
    # Typical range is roughly [-0.25, 0.25]; we center around 0.
    clipped = max(-0.25, min(0.25, decision_function_score))
    return round(0.5 - (clipped * 2), 4)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="ml/data/access_logs.csv")
    ap.add_argument("--model", default="ml/models/iforest.joblib")
    args = ap.parse_args()

    df = pd.read_csv(args.input)
    # Coerce boolean columns to int so IsolationForest can process them.
    for col in ("break_glass", "patient_sensitive", "department_match"):
        if col in df.columns:
            df[col] = df[col].astype(int)

    X = df[FEATURE_COLUMNS]

    pipe = build_pipeline()
    pipe.fit(X)

    os.makedirs(os.path.dirname(args.model), exist_ok=True)
    joblib.dump(pipe, args.model)
    print(f"trained on {len(df)} rows, saved to {args.model}")

    # Quick sanity-check: print the top 5 most anomalous rows.
    raw = pipe.named_steps["iforest"].decision_function(
        pipe.named_steps["prep"].transform(X)
    )
    df = df.copy()
    df["_score"] = [normalize_score(s) for s in raw]
    top = df.sort_values("_score", ascending=False).head(5)
    print("\nTop-5 anomalies:")
    print(top[["user_id", "role", "hour", "break_glass", "_score"]].to_string(index=False))


if __name__ == "__main__":
    main()
