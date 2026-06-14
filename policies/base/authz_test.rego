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

# Test: Tier 1 hour limit denies even a valid nurse
test_tier1_hour_limit_deny if {
    result.allow == false with input as {
        "subject": {
            "has_roles": true,
            "roles": ["nurse"],
            "fhir_context": {"department": "cardiology", "role": "nurse"},
            "break_glass": {"enabled": false},
            "tenant_id": "hospital-a",
            "purpose_of_use": "TREATMENT",
            "access_counts": {"last_minute": 5, "last_hour": 101},
            "is_after_hours": false
        },
        "resource": {"type": "Patient", "patient_id": "patient-1"},
        "request": {"method": "GET", "path": "/fhir/r4/Patient/patient-1", "path_parts": ["Patient", "patient-1"]}
    }
}

# Test: Tier 1 hour limit sets reason to tier1_denied
test_tier1_hour_limit_reason if {
    result.reason == "tier1_denied" with input as {
        "subject": {
            "has_roles": true,
            "roles": ["nurse"],
            "fhir_context": {"department": "cardiology", "role": "nurse"},
            "break_glass": {"enabled": false},
            "tenant_id": "hospital-a",
            "purpose_of_use": "TREATMENT",
            "access_counts": {"last_minute": 5, "last_hour": 101},
            "is_after_hours": false
        },
        "resource": {"type": "Patient", "patient_id": "patient-1"},
        "request": {"method": "GET", "path": "/fhir/r4/Patient/patient-1", "path_parts": ["Patient", "patient-1"]}
    }
}

# Test: after-hours limit denies non-admin with >20 requests/hour
test_tier1_afterhours_deny if {
    result.allow == false with input as {
        "subject": {
            "has_roles": true,
            "roles": ["nurse"],
            "fhir_context": {"department": "cardiology", "role": "nurse"},
            "break_glass": {"enabled": false},
            "tenant_id": "hospital-a",
            "purpose_of_use": "TREATMENT",
            "access_counts": {"last_minute": 2, "last_hour": 21},
            "is_after_hours": true
        },
        "resource": {"type": "Patient", "patient_id": "patient-1"},
        "request": {"method": "GET", "path": "/fhir/r4/Patient/patient-1", "path_parts": ["Patient", "patient-1"]}
    }
}

# Test: after-hours limit does NOT deny admin
test_tier1_afterhours_admin_allow if {
    result.allow == true with input as {
        "subject": {
            "has_roles": true,
            "roles": ["admin"],
            "fhir_context": {"department": "IT", "role": "admin"},
            "break_glass": {"enabled": false},
            "tenant_id": "hospital-a",
            "purpose_of_use": "OPERATIONS",
            "access_counts": {"last_minute": 2, "last_hour": 21},
            "is_after_hours": true
        },
        "resource": {"type": "Patient", "patient_id": "patient-1"},
        "request": {"method": "GET", "path": "/fhir/r4/Patient/patient-1", "path_parts": ["Patient", "patient-1"]}
    }
}

# Test: break-glass bypasses Tier 1 hour limit
test_tier1_breakglass_bypasses if {
    result.allow == true with input as {
        "subject": {
            "has_roles": true,
            "roles": ["nurse", "can_break_glass"],
            "fhir_context": {"department": "cardiology", "role": "nurse"},
            "break_glass": {"enabled": true, "justification": "Code blue"},
            "tenant_id": "hospital-a",
            "purpose_of_use": "EMERGENCY",
            "access_counts": {"last_minute": 5, "last_hour": 200},
            "is_after_hours": true
        },
        "resource": {"type": "Patient", "patient_id": "patient-1"},
        "request": {"method": "GET", "path": "/fhir/r4/Patient/patient-1", "path_parts": ["Patient", "patient-1"]}
    }
}


# ─── FIX-2 consent CodeableConcept tests ──────────────────────────────────────

test_purpose_allowed_nested_codeableconcept if {
    purpose_allowed with input as {
        "subject": {"purpose_of_use": "TREAT"},
        "resource": {
            "consent": {
                "allowed_purposes": [
                    {
                        "coding": [
                            {"system": "http://hl7.org/fhir/v3/ActReason", "code": "TREAT"},
                            {"system": "http://hl7.org/fhir/v3/ActReason", "code": "ETREAT"}
                        ]
                    }
                ]
            }
        }
    }
}

test_purpose_denied_no_matching_code if {
    not purpose_allowed with input as {
        "subject": {"purpose_of_use": "RESEARCH"},
        "resource": {
            "consent": {
                "allowed_purposes": [
                    {
                        "coding": [
                            {"system": "http://hl7.org/fhir/v3/ActReason", "code": "TREAT"}
                        ]
                    }
                ]
            }
        }
    }
}

# Regression guard: flat string array must NOT silently match the nested rule.
test_purpose_flat_array_shape_does_not_match if {
    not purpose_allowed with input as {
        "subject": {"purpose_of_use": "TREAT"},
        "resource": {
            "consent": {
                "allowed_purposes": ["TREAT", "ETREAT"]
            }
        }
    }
}
