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
# Allow rules
# -----------------------------------------------------------

# Standard access: user has roles + passes resource & department checks
allow if {
    input.subject.has_roles
    valid_role_for_resource
    valid_department_access
    not is_sensitive_patient
}

# Break-glass override
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
}

# Doctors see address masked but not telecom
mask := ["address"] if {
    input.subject.fhir_context.role == "doctor"
    not input.subject.break_glass.enabled
}

# Break-glass: no masking at all (mask stays default [])

# -----------------------------------------------------------
# Reason
# -----------------------------------------------------------
reason := "no_roles" if {
    not input.subject.has_roles
}

reason := "break_glass_access" if {
    input.subject.break_glass.enabled
    allow
}

reason := "authorized" if {
    allow
    not input.subject.break_glass.enabled
}

reason := "access_denied" if {
    not allow
    input.subject.has_roles
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

valid_department_access if {
    "admin" in input.subject.roles
}

valid_department_access if {
    input.subject.fhir_context.department == input.resource.department
}

is_sensitive_patient if {
    input.resource.patient_id in data.sensitive_patients
}

# -----------------------------------------------------------
# Bundled decision object (queried at /v1/data/authz/decision)
# -----------------------------------------------------------
decision := {
    "allow": allow,
    "remove": remove,
    "mask": mask,
    "reason": reason,
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
