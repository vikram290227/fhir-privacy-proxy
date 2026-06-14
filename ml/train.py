"""
Training pipeline for the FHIR access risk model.

Usage:
    python ml/train.py --data /path/to/audit_logs.csv --output model.json

CSV columns required:
    hour_of_day, day_of_week, accesses_last_hour, accesses_today,
    is_typical_department, has_care_team_relation, is_break_glass,
    label  (0=legitimate, 1=inappropriate)
"""
import argparse

import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

try:
    import shap  # type: ignore
    _HAS_SHAP = True
except ImportError:
    _HAS_SHAP = False

FEATURE_COLS = [
    "hour_of_day",
    "day_of_week",
    "accesses_last_hour",
    "accesses_today",
    "is_typical_department",
    "has_care_team_relation",
    "is_break_glass",
]


def train(data_path: str, output_path: str) -> None:
    df = pd.read_csv(data_path)
    assert "label" in df.columns, "CSV must have a 'label' column (0 or 1)"

    X = df[FEATURE_COLS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = xgb.XGBClassifier(
        objective="binary:logistic",
        max_depth=6,
        learning_rate=0.1,
        n_estimators=200,
        scale_pos_weight=(y_train == 0).sum() / max((y_train == 1).sum(), 1),
        eval_metric="auc",
        early_stopping_rounds=20,
        verbosity=0,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    y_prob = model.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_prob)
    print(f"AUC-ROC: {auc:.4f}")
    print(classification_report(y_test, (y_prob > 0.5).astype(int)))

    model.save_model(output_path)
    print(f"Model saved to {output_path}")

    if _HAS_SHAP:
        try:
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(X_test.iloc[:100])
            shap.summary_plot(
                shap_values,
                X_test.iloc[:100],
                feature_names=FEATURE_COLS,
                show=False,
            )
            print("SHAP summary generated")
        except Exception as exc:
            print(f"SHAP summary skipped: {exc}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--output", default="model.json")
    args = parser.parse_args()
    train(args.data, args.output)
