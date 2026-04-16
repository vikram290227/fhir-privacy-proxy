# Snapshot: policies/versions/v1 — the original static RBAC policy.
# This version is kept on disk so the policyversion manager can roll
# back to it if v2 (risk-aware) causes operational issues.
package authz

import future.keywords.if
import future.keywords.in

default allow := false
default remove := []
default mask := []

allow if {
    input.subject.has_roles
    valid_role_for_resource
    valid_department_access
    not is_sensitive_patient
}

allow if {
    input.subject.break_glass.enabled
    "can_break_glass" in input.subject.roles
    input.subject.has_roles
}

remove := ["identifier"] if {
    input.subject.fhir_context.role == "nurse"
    not input.subject.break_glass.enabled
}

mask := ["telecom", "address"] if {
    input.subject.fhir_context.role == "nurse"
    not input.subject.break_glass.enabled
}

mask := ["address"] if {
    input.subject.fhir_context.role == "doctor"
    not input.subject.break_glass.enabled
}

reason := "no_roles" if { not input.subject.has_roles }
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

valid_role_for_resource if {
    input.subject.fhir_context.role == "nurse"
    input.request.path_parts[0] in ["Patient", "Observation", "Condition"]
}
valid_role_for_resource if {
    input.subject.fhir_context.role == "doctor"
}
valid_department_access if { "admin" in input.subject.roles }
valid_department_access if {
    input.subject.fhir_context.department != "UNKNOWN"
    input.subject.fhir_context.department != ""
}

# Per-tenant sensitive-patient lookup — data.json is keyed by tenant_id.
is_sensitive_patient if {
    input.resource.patient_id in data[input.subject.tenant_id].sensitive_patients
}

decision := {
    "allow": allow,
    "remove": remove,
    "mask": mask,
    "reason": reason,
}
