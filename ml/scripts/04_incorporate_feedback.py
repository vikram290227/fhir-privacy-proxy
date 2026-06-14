"""Active learning merge: incorporate Privacy Officer feedback into the training set and retrain.

Usage:
    python ml/scripts/04_incorporate_feedback.py \
        --input ml/data/access_logs.csv \
        --feedback ml/data/feedback.ndjson \
        --model ml/models/iforest.joblib

The script is a thin wrapper around retrain_nightly.retrain() that adds
logging and a --dry-run flag so Privacy Officers can preview what rows
would be merged before committing a model update.
"""
import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# Allow running from repo root without installing the package.
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ml.retrain_nightly import retrain  # noqa: E402


def _count_feedback_rows(feedback_path: str) -> tuple[int, int]:
    """Return (legitimate, anomalous) counts from the feedback NDJSON."""
    legit, anomalous = 0, 0
    try:
        with open(feedback_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    if row.get("was_legitimate"):
                        legit += 1
                    else:
                        anomalous += 1
                except json.JSONDecodeError:
                    log.warning("skipping malformed feedback line: %r", line[:80])
    except FileNotFoundError:
        log.warning("feedback file not found: %s", feedback_path)
    return legit, anomalous


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge Privacy Officer feedback and retrain.")
    parser.add_argument("--input", default="ml/data/access_logs.csv", help="Base training CSV")
    parser.add_argument("--feedback", default="ml/data/feedback.ndjson", help="Feedback NDJSON")
    parser.add_argument("--model", default="ml/models/iforest.joblib", help="Output model path")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview feedback counts, do not retrain",
    )
    args = parser.parse_args()

    legit, anomalous = _count_feedback_rows(args.feedback)
    log.info("feedback summary: %d legitimate, %d anomalous rows", legit, anomalous)

    if args.dry_run:
        log.info(
            "dry-run: skipping retrain. Would inject %d rows (%d×3 anomalous duplicates).",
            legit + anomalous, anomalous,
        )
        return

    if legit + anomalous == 0:
        log.warning("no feedback rows found — retrain will use base training set only")

    meta = retrain(
        input_path=args.input,
        feedback_path=args.feedback,
        model_path=args.model,
    )

    log.info("retrain complete")
    log.info("  training rows : %d", meta.get("training_rows", "?"))
    log.info("  feedback rows : %d", meta.get("feedback_rows", "?"))
    log.info("  anomaly rate  : %.4f", meta.get("anomaly_rate", 0))
    log.info("  model path    : %s", args.model)
    log.info("  trained at    : %s", meta.get("last_trained_ts", "?"))


if __name__ == "__main__":
    main()
