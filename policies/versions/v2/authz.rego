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
# These can be overridden per tenant by editing policies/data.json.
risk_deny_threshold := 0.85
risk_mask_threshold := 0.6

risk_score := s if {
    s := input.subject.risk.score
} else := 0

# -----------------------------------------------------------
# Allow rules
# -----------------------------------------------------------

# Standard access: user has roles + passes resource & department checks
allow if {
    input.subject.has_roles
    valid_role_for_resource
    valid_department_access
    not is_sensitive_patient
    risk_score < risk_deny_threshold
}

# Admin bypass (still blocked by very high risk score)
allow if {
    "admin" in input.subject.roles
    input.subject.has_roles
    risk_score < risk_deny_threshold
}

# Break-glass override — bypasses sensitivity and risk thresholds,
# but is heavily audited and triggers mandatory review.
allow if {
    input.subject.break_glass.enabled
    "can_break_glass" in input.subject.roles
    input.subject.has_roles
}

# -----------------------------------------------------------
# Redaction: remove paths (field deleted from response)
# -----------------------------------------------------------

# Nurses cannot see patient identifiers (SSN, MRN, etc.)
remove := ["identifier"] if {
    input.subject.fhir_context.role == "nurse"
    not input.subject.break_glass.enabled
}

# -----------------------------------------------------------
# Redaction: mask paths (value replaced with ***REDACTED***)
# -----------------------------------------------------------

# Nurses see telecom and address masked
mask := ["telecom", "address"] if {
    input.subject.fhir_context.role == "nurse"
    not input.subject.break_glass.enabled
    risk_score < risk_mask_threshold
}

# Doctors see address masked but not telecom
mask := ["address"] if {
    input.subject.fhir_context.role == "doctor"
    not input.subject.break_glass.enabled
    risk_score < risk_mask_threshold
}

# Adaptive authorization — when the risk score is elevated but not
# high enough to deny, widen the mask set for anyone who is not
# breaking glass (admins included).
mask := ["telecom", "address", "identifier", "birthDate"] if {
    risk_score >= risk_mask_threshold
    risk_score < risk_deny_threshold
    not input.subject.break_glass.enabled
}

# Break-glass: no masking at all (mask stays default [])

# -----------------------------------------------------------
# Reason
# -----------------------------------------------------------
reason := "no_roles" if {
    not input.subject.has_roles
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
    risk_score < risk_deny_threshold
}

# -----------------------------------------------------------
# Helper rules
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

# Subject must have a known department assigned (not UNKNOWN or empty).
valid_department_access if {
    input.subject.fhir_context.department != "UNKNOWN"
    input.subject.fhir_context.department != ""
}

# Per-tenant sensitive-patient lookup. data.json is keyed by tenant_id
# ("hospital-a" / "hospital-b"), enforced at authz time via the
# verified JWT issuer.
is_sensitive_patient if {
    input.resource.patient_id in data[input.subject.tenant_id].sensitive_patients
}

# -----------------------------------------------------------
# Bundled decision object (queried at /v1/data/authz/decision)
# -----------------------------------------------------------
decision := {
    "allow": allow,
    "remove": remove,
    "mask": mask,
    "reason": reason,
    "risk_score": risk_score,
}

# -----------------------------------------------------------
# Audit annotations
# -----------------------------------------------------------
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
