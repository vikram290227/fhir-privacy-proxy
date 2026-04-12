"""
Access log schema for ML-driven anomaly detection.

Every access event that flows through the FHIR privacy proxy is
recorded with the fields below so the Isolation Forest model can be
trained on realistic usage patterns.  The schema is also the contract
between the Go proxy's risk client and the Python scoring service,
so any change here MUST be mirrored in internal/risk/client.go.
"""

from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class AccessLog:
    # Actor -----------------------------------------------------------
    user_id: str                 # Keycloak subject id
    role: str                    # nurse | doctor | admin
    department: str              # cardiology | oncology | administration | ...

    # Target ----------------------------------------------------------
    patient_id: str              # FHIR Patient id, may be empty
    resource_type: str           # Patient | Observation | Condition | ...
    action: str                  # read | write

    # Context ---------------------------------------------------------
    hour: int                    # 0..23 local hour of the access
    day_of_week: int             # 0..6 where 0 = Sunday
    break_glass: bool            # emergency override used?
    patient_sensitive: bool = False
    department_match: bool = True   # does subject dept == patient dept?
    ip_country: Optional[str] = None

    # Outcome ---------------------------------------------------------
    decision: Optional[str] = None  # allow | deny | mask
    tenant_id: Optional[str] = None
    timestamp: Optional[str] = None  # ISO-8601 UTC

    # Feedback (used by retraining) ----------------------------------
    review_label: Optional[str] = None  # "correct" | "incorrect" | None

    def to_dict(self):
        return asdict(self)


# Features used as input to the Isolation Forest. Categorical values
# are one-hot encoded by the trainer.
FEATURE_COLUMNS = [
    "hour",
    "day_of_week",
    "break_glass",
    "patient_sensitive",
    "department_match",
    "role",
    "action",
    "resource_type",
]

# Numeric columns are passed directly; categorical columns are fed
# through the ColumnTransformer.
NUMERIC_COLUMNS = [
    "hour",
    "day_of_week",
    "break_glass",
    "patient_sensitive",
    "department_match",
]
CATEGORICAL_COLUMNS = [
    "role",
    "action",
    "resource_type",
]
