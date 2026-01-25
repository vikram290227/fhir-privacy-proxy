import future.keywords.if
import future.keywords.in

# Default deny
default allow = false

# Allow if user has roles and passes all checks
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

# Helper rules
valid_role_for_resource if {
    input.subject.fhir_context.role == "nurse"
    input.resource.type in ["Patient", "Observation", "Condition"]
}

valid_role_for_resource if {
    input.subject.fhir_context.role == "doctor"
    # Doctors can access all resource types
}

valid_department_access if {
    input.subject.fhir_context.department == input.resource.department
}

valid_department_access if {
    # Admins can access all departments
    "admin" in input.subject.roles
}

is_sensitive_patient if {
    input.resource.patient_id in data.sensitive_patients
}

# Audit annotations
annotations[msg] if {
    input.subject.break_glass.enabled
    msg := sprintf("BREAK_GLASS: %s accessed %s/%s - %s",
        [input.subject.subject_id, 
         input.resource.type,
         input.resource.id,
         input.subject.break_glass.justification])
}
