"""
Generates synthetic FHIR access log data for ML model development.
Labels are deterministic: high-risk patterns -> label=1, normal -> label=0.

Usage:
    python ml/generate_synthetic_data.py --samples 10000 --output synthetic_logs.csv
"""
import argparse

import numpy as np
import pandas as pd


def generate(n_samples: int, output_path: str, seed: int = 42) -> None:
    rng = np.random.default_rng(seed)
    n_normal = int(n_samples * 0.92)
    n_anomalous = n_samples - n_normal

    def normal_sample(n: int) -> pd.DataFrame:
        return pd.DataFrame({
            "hour_of_day":            rng.integers(7, 19, n),
            "day_of_week":            rng.integers(0, 5, n),
            "accesses_last_hour":     rng.integers(1, 25, n),
            "accesses_today":         rng.integers(5, 80, n),
            "is_typical_department":  rng.choice([True, False], n, p=[0.9, 0.1]),
            "has_care_team_relation": rng.choice([True, False], n, p=[0.7, 0.3]),
            "is_break_glass":         rng.choice([True, False], n, p=[0.02, 0.98]),
            "label": 0,
        })

    def anomalous_sample(n: int) -> pd.DataFrame:
        return pd.DataFrame({
            "hour_of_day":            rng.choice([0, 1, 2, 3, 22, 23], n),
            "day_of_week":            rng.integers(0, 7, n),
            "accesses_last_hour":     rng.integers(50, 200, n),
            "accesses_today":         rng.integers(100, 500, n),
            "is_typical_department":  rng.choice([True, False], n, p=[0.2, 0.8]),
            "has_care_team_relation": rng.choice([True, False], n, p=[0.1, 0.9]),
            "is_break_glass":         np.zeros(n, dtype=bool),
            "label": 1,
        })

    df = pd.concat(
        [normal_sample(n_normal), anomalous_sample(n_anomalous)],
        ignore_index=True,
    )
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df)} samples ({n_anomalous} anomalous) -> {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=10000)
    parser.add_argument("--output", default="synthetic_logs.csv")
    args = parser.parse_args()
    generate(args.samples, args.output)
