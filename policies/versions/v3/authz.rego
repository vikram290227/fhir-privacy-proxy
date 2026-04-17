# Snapshot: policies/versions/v3 — tightens nurse-scope redaction by
# adding birthDate to the baseline mask list. Everything else is
# inherited verbatim from v2 (risk-aware thresholds, per-tenant
# sensitive patient lookup, break-glass handling, consent enforcement).
#
# Rationale: HIPAA treats birthDate as a quasi-identifier (one of the
# 18 Safe Harbor elements). v2 only masked it under elevated risk;
# v3 makes it masked by default for the nurse role, bringing the
# de-identification posture closer to minimum-necessary.
package authz

import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------
# Defaults
# -----------------------------------------------------------
default allow := false
default remove := []
default mask := []

# -----------------------------------------------------------
# Thresholds for risk-aware / adaptive authorization
# -----------------------------------------------------------
risk_deny_threshold := 0.85
risk_mask_threshold := 0.6

risk_score := s if {
    s := input.subject.risk.score
} else := 0

# -----------------------------------------------------------
# Allow rules
# -----------------------------------------------------------
allow if {
    input.subject.has_roles
    valid_role_for_resource
    valid_department_access
    not is_sensitive_patient
    consent_permits
    risk_score < risk_deny_threshold
}

allow if {
    "admin" in input.subject.roles
    input.subject.has_roles
    consent_permits
    risk_score < risk_deny_threshold
}

allow if {
    input.subject.break_glass.enabled
    "can_break_glass" in input.subject.roles
    input.subject.has_roles
}

# -----------------------------------------------------------
# Redaction: remove paths (v3 unchanged from v2)
# -----------------------------------------------------------
remove := ["identifier"] if {
    input.subject.fhir_context.role == "nurse"
    not input.subject.break_glass.enabled
}

# -----------------------------------------------------------
# Redaction: mask paths — v3 change
# -----------------------------------------------------------
# v3: nurses now have birthDate masked at the baseline, not only at
# elevated risk. This is the whole point of the v3 bundle.
mask := ["telecom", "address", "birthDate"] if {
    input.subject.fhir_context.role == "nurse"
    not input.subject.break_glass.enabled
    risk_score < risk_mask_threshold
}

# Doctor mask unchanged from v2.
mask := ["address"] if {
    input.subject.fhir_context.role == "doctor"
    not input.subject.break_glass.enabled
    risk_score < risk_mask_threshold
}

# Adaptive authorization — mask list under elevated risk stays the
# same as v2. birthDate was already in this list there, so v3's
# baseline now converges with v2's elevated-risk baseline for nurses.
mask := ["telecom", "address", "identifier", "birthDate"] if {
    risk_score >= risk_mask_threshold
    risk_score < risk_deny_threshold
    not input.subject.break_glass.enabled
}

# -----------------------------------------------------------
# Reason
# -----------------------------------------------------------
reason := "no_roles" if {
    not input.subject.has_roles
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

reason := "break_glass_access" if {
    input.subject.break_glass.enabled
    allow
}

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

reason := "access_denied" if {
    not allow
    input.subject.has_roles
    consent_permits
    risk_score < risk_deny_threshold
}

# -----------------------------------------------------------
# Consent rules
# -----------------------------------------------------------
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
    input.subject.purpose_of_use in input.resource.consent.allowed_purposes
}

consent_permits if {
    input.subject.purpose_of_use == "EMERGENCY"
}

# -----------------------------------------------------------
# Helper rules (unchanged from v2)
# -----------------------------------------------------------
valid_role_for_resource if {
    input.subject.fhir_context.role == "nurse"
    input.request.path_parts[0] in ["Patient", "Observation", "Condition"]
}

valid_role_for_resource if {
    input.subject.fhir_context.role == "doctor"
}

valid_role_for_resource if {
    "admin" in input.subject.roles
}

valid_department_access if {
    "admin" in input.subject.roles
}

valid_department_access if {
    input.subject.fhir_context.department != "UNKNOWN"
    input.subject.fhir_context.department != ""
}

is_sensitive_patient if {
    input.resource.patient_id in data[input.subject.tenant_id].sensitive_patients
}

# -----------------------------------------------------------
# Bundled decision object
# -----------------------------------------------------------
decision := {
    "allow": allow,
    "remove": remove,
    "mask": mask,
    "reason": reason,
    "risk_score": risk_score,
}

annotations[msg] if {
    input.subject.break_glass.enabled
    msg := sprintf("BREAK_GLASS: %s accessed %s - %s",
        [input.subject.subject_id,
         input.request.path,
         input.subject.break_glass.justification])
}

annotations[msg] if {
    risk_score >= risk_mask_threshold
    msg := sprintf("ELEVATED_RISK: score=%v subject=%s path=%s",
        [risk_score, input.subject.subject_id, input.request.path])
}

annotations[msg] if {
    input.resource.consent
    not consent_permits
    msg := sprintf("CONSENT_DENIED: subject=%s patient=%s purpose=%s",
        [input.subject.subject_id,
         input.resource.patient_id,
         input.subject.purpose_of_use])
}

annotations[msg] if {
    input.subject.purpose_of_use == "EMERGENCY"
    input.resource.consent
    msg := sprintf("EMERGENCY_CONSENT_BYPASS: subject=%s patient=%s",
        [input.subject.subject_id,
         input.resource.patient_id])
}
