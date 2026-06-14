package firewall.decision

import future.keywords.if
import future.keywords.in

# ─── defaults ──────────────────────────────────────────────
default allow     := false
default remove    := []
default mask      := []
default reason    := "default-deny"

# ─── risk thresholds ──────────────────────────────────────
risk_deny_threshold := 0.85
risk_mask_threshold := 0.6

# Tier 1 hard-deny thresholds — enforced without ML, from Redis counters.
tier1_hour_limit      := 100  # requests/hour before unconditional deny
tier1_afterhours_limit := 20  # requests/hour during off-hours before deny
tier1_day_limit       := 500  # requests/day before unconditional deny

risk_score := s if {
    s := input.subject.risk.score
    not input.subject.risk.unavailable
} else := 0

# ─── Tier 1: counter-based hard-deny rules ────────────────
# These fire regardless of ML score, using Redis sliding-window counters
# surfaced via input.subject.access_counts. Break-glass bypasses Tier 1.

tier1_deny if {
    input.subject.access_counts.last_hour > tier1_hour_limit
    not input.subject.break_glass.enabled
}

tier1_deny if {
    input.subject.is_after_hours
    input.subject.access_counts.last_hour > tier1_afterhours_limit
    not "admin" in input.subject.roles
    not input.subject.break_glass.enabled
}

tier1_deny if {
    input.subject.access_counts.last_day > tier1_day_limit
    not input.subject.break_glass.enabled
}

# ─── allow: normal clinical access ────────────────────────
allow if {
    input.subject.has_roles
    count(input.subject.roles) > 0
    valid_role_for_resource
    valid_department_access
    not is_sensitive_patient
    consent_permits
    not tier1_deny
    not data.firewall.bulk_access.bulk_deny
    risk_score < risk_deny_threshold
}

# allow: break-glass override
allow if {
    input.subject.break_glass.enabled
    "can_break_glass" in input.subject.roles
    input.subject.has_roles
}

# allow: admin always has access (still blocked by very high risk and Tier 1)
allow if {
    "admin" in input.subject.roles
    input.subject.has_roles
    consent_permits
    not tier1_deny
    not data.firewall.bulk_access.bulk_deny
    risk_score < risk_deny_threshold
}

# ─── role-resource rules ───────────────────────────────────
valid_role_for_resource if {
    "nurse" in input.subject.roles
    input.resource.type in {"Patient", "Observation", "Condition", "MedicationRequest", "AllergyIntolerance"}
}

valid_role_for_resource if {
    "doctor" in input.subject.roles
}

valid_role_for_resource if {
    "admin" in input.subject.roles
}

# ─── department access ─────────────────────────────────────
valid_department_access if {
    "admin" in input.subject.roles
}

valid_department_access if {
    input.subject.fhir_context.department != "UNKNOWN"
    input.subject.fhir_context.department != ""
}

# ─── sensitive patient protection ─────────────────────────
is_sensitive_patient if {
    input.resource.patient_id in data[input.subject.tenant_id].sensitive_patients
}

# ─── consent rules ────────────────────────────────────────
default consent_permits := true

consent_permits := false if {
    input.resource.consent
    input.resource.consent.status in ["inactive", "rejected"]
}

consent_permits := false if {
    input.resource.consent
    input.resource.consent.status == "active"
    count(input.resource.consent.allowed_purposes) > 0
    not purpose_allowed
}

purpose_allowed if {
    some concept in input.resource.consent.allowed_purposes
    some coding in concept.coding
    coding.code == input.subject.purpose_of_use
}

consent_permits if {
    input.subject.purpose_of_use == "EMERGENCY"
}

# ─── field redaction: remove ──────────────────────────────
remove := ["$.telecom"] if {
    input.resource.type == "Patient"
    "nurse" in input.subject.roles
    not "admin" in input.subject.roles
    not input.subject.break_glass.enabled
}

# ─── field redaction: mask ────────────────────────────────
mask := ["$.identifier[0].value"] if {
    input.resource.type == "Patient"
    not "admin" in input.subject.roles
    risk_score < risk_mask_threshold
    not input.subject.break_glass.enabled
}

mask := ["$.telecom", "$.address", "$.identifier[0].value", "$.birthDate"] if {
    risk_score >= risk_mask_threshold
    risk_score < risk_deny_threshold
    not input.subject.break_glass.enabled
}

# ─── reason ───────────────────────────────────────────────
reason := "authorized" if {
    allow
    not input.subject.break_glass.enabled
    risk_score < risk_mask_threshold
}

reason := "elevated_risk_authorized" if {
    allow
    risk_score >= risk_mask_threshold
    risk_score < risk_deny_threshold
}

reason := "break-glass-access" if {
    input.subject.break_glass.enabled
    allow
}

reason := "no-roles" if {
    not input.subject.has_roles
}

reason := "insufficient-role" if {
    input.subject.has_roles
    not valid_role_for_resource
}

reason := "sensitive-patient" if {
    valid_role_for_resource
    is_sensitive_patient
}

reason := "consent_denied" if {
    input.subject.has_roles
    not consent_permits
    not input.subject.break_glass.enabled
}

reason := "high_risk_denied" if {
    risk_score >= risk_deny_threshold
    not input.subject.break_glass.enabled
}

reason := "tier1_denied" if {
    tier1_deny
    not input.subject.break_glass.enabled
}

reason := "bulk_denied" if {
    data.firewall.bulk_access.bulk_deny
    not input.subject.break_glass.enabled
}

# ─── final result object ──────────────────────────────────
result := {
    "allow":       allow,
    "remove":      remove,
    "mask":        mask,
    "reason":      reason,
    "risk_score":  risk_score,
    "tier1_deny":  tier1_deny,
    "bulk_warn":   data.firewall.bulk_access.bulk_warn,
}
