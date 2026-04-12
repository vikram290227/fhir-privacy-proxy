"""
Synthetic healthcare access-log generator.

Produces a CSV of access events spanning normal and anomalous
behaviour, intended for training the Isolation Forest anomaly
detector. Normal patterns dominate; ~2% of rows are injected as
anomalies to mimic the sparsity of real insider-threat data.

Usage:
    python ml/generate_dataset.py --rows 20000 --out ml/data/access_logs.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import random
from datetime import datetime, timedelta, timezone

ROLES = ["nurse", "doctor", "admin"]
DEPARTMENTS = ["cardiology", "oncology", "pediatrics", "emergency", "administration"]
RESOURCES = ["Patient", "Observation", "Condition", "MedicationRequest"]
ACTIONS = ["read", "write"]


def _normal_row(rng: random.Random) -> dict:
    role = rng.choices(ROLES, weights=[0.6, 0.35, 0.05])[0]
    dept = rng.choice(DEPARTMENTS[:4])  # not administration
    resource = rng.choice(RESOURCES)
    action = "read" if rng.random() < 0.85 else "write"
    # Normal hours: 07:00-19:00 on weekdays
    day = rng.randint(1, 5)  # Mon-Fri
    hour = rng.randint(7, 19)
    return {
        "user_id": f"{role}{rng.randint(1, 20)}",
        "role": role,
        "department": dept,
        "patient_id": f"p{rng.randint(1, 500)}",
        "resource_type": resource,
        "action": action,
        "hour": hour,
        "day_of_week": day,
        "break_glass": False,
        "patient_sensitive": rng.random() < 0.05,
        "department_match": True,
        "tenant_id": "hospital-a",
        "decision": "allow",
    }


def _anomalous_row(rng: random.Random) -> dict:
    # Anomaly flavours:
    #   - late-night access
    #   - department mismatch
    #   - unusually high volume of writes by a nurse
    #   - sensitive patient access outside emergency
    flavour = rng.choice(["night", "mismatch", "nurse_write", "sensitive"])
    row = _normal_row(rng)

    if flavour == "night":
        row["hour"] = rng.choice([0, 1, 2, 3, 4, 23])
        row["day_of_week"] = rng.choice([0, 6])  # weekend
    elif flavour == "mismatch":
        row["department"] = rng.choice(DEPARTMENTS)
        row["department_match"] = False
    elif flavour == "nurse_write":
        row["role"] = "nurse"
        row["action"] = "write"
        row["resource_type"] = rng.choice(["MedicationRequest", "Observation"])
    elif flavour == "sensitive":
        row["patient_sensitive"] = True
        row["break_glass"] = False
    return row


def generate(rows: int, seed: int = 42, anomaly_rate: float = 0.02) -> list[dict]:
    rng = random.Random(seed)
    data: list[dict] = []
    start = datetime.now(timezone.utc) - timedelta(days=30)
    for i in range(rows):
        if rng.random() < anomaly_rate:
            row = _anomalous_row(rng)
        else:
            row = _normal_row(rng)
        ts = start + timedelta(seconds=i * 60)
        row["timestamp"] = ts.isoformat()
        data.append(row)
    return data


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=20000)
    ap.add_argument("--out", type=str, default="ml/data/access_logs.csv")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--anomaly-rate", type=float, default=0.02)
    args = ap.parse_args()

    data = generate(args.rows, args.seed, args.anomaly_rate)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(data[0].keys()))
        writer.writeheader()
        writer.writerows(data)
    print(f"wrote {len(data)} rows to {args.out}")


if __name__ == "__main__":
    main()
