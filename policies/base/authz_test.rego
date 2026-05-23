package firewall.decision

import future.keywords.if

# Test: nurse with correct role and department gets access
test_nurse_allow if {
    result.allow == true with input as {
        "subject": {
            "has_roles": true,
            "roles": ["nurse"],
            "fhir_context": {"department": "cardiology", "role": "nurse"},
            "break_glass": {"enabled": false},
            "tenant_id": "hospital-a",
            "purpose_of_use": "TREATMENT"
        },
        "resource": {"type": "Patient", "patient_id": "patient-1"},
        "request": {"method": "GET", "path": "/fhir/r4/Patient/patient-1", "path_parts": ["Patient", "patient-1"]}
    }
}

# Test: no roles -> deny
test_no_roles_deny if {
    result.allow == false with input as {
        "subject": {
            "has_roles": false,
            "roles": [],
            "fhir_context": {"department": "cardiology", "role": ""},
            "break_glass": {"enabled": false},
            "tenant_id": "hospital-a",
            "purpose_of_use": "TREATMENT"
        },
        "resource": {"type": "Patient", "patient_id": "patient-1"},
        "request": {"method": "GET", "path": "/fhir/r4/Patient/patient-1", "path_parts": ["Patient", "patient-1"]}
    }
}

# Test: break-glass -> allow
test_break_glass_allow if {
    result.allow == true with input as {
        "subject": {
            "has_roles": true,
            "roles": ["nurse", "can_break_glass"],
            "fhir_context": {"department": "cardiology", "role": "nurse"},
            "break_glass": {"enabled": true, "justification": "Emergency trauma"},
            "tenant_id": "hospital-a",
            "purpose_of_use": "EMERGENCY"
        },
        "resource": {"type": "Patient", "patient_id": "patient-1"},
        "request": {"method": "GET", "path": "/fhir/r4/Patient/patient-1", "path_parts": ["Patient", "patient-1"]}
    }
}

# Test: nurse gets telecom removed outside ED
test_nurse_telecom_removed if {
    result.remove == ["$.telecom"] with input as {
        "subject": {
            "has_roles": true,
            "roles": ["nurse"],
            "fhir_context": {"department": "cardiology", "role": "nurse"},
            "break_glass": {"enabled": false},
            "tenant_id": "hospital-a",
            "purpose_of_use": "TREATMENT"
        },
        "resource": {"type": "Patient", "patient_id": "patient-1"},
        "request": {"method": "GET", "path": "/fhir/r4/Patient/patient-1", "path_parts": ["Patient", "patient-1"]}
    }
}

# Test: admin always has access
test_admin_allow if {
    result.allow == true with input as {
        "subject": {
            "has_roles": true,
            "roles": ["admin"],
            "fhir_context": {"department": "IT", "role": "admin"},
            "break_glass": {"enabled": false},
            "tenant_id": "hospital-a",
            "purpose_of_use": "OPERATIONS"
        },
        "resource": {"type": "Patient", "patient_id": "patient-1"},
        "request": {"method": "GET", "path": "/fhir/r4/Patient/patient-1", "path_parts": ["Patient", "patient-1"]}
    }
}

# Test: no-roles reason string matches
test_no_roles_reason if {
    result.reason == "no-roles" with input as {
        "subject": {
            "has_roles": false,
            "roles": [],
            "fhir_context": {"department": "cardiology", "role": ""},
            "break_glass": {"enabled": false},
            "tenant_id": "hospital-a",
            "purpose_of_use": "TREATMENT"
        },
        "resource": {"type": "Patient", "patient_id": "patient-1"},
        "request": {"method": "GET", "path": "/fhir/r4/Patient/patient-1", "path_parts": ["Patient", "patient-1"]}
    }
}
