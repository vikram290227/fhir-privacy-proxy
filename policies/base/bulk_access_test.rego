package firewall.bulk_access

import future.keywords.if

# Shared base subject — normal nurse, no break-glass.
_nurse_subject := {
    "has_roles": true,
    "roles": ["nurse"],
    "fhir_context": {"department": "cardiology", "role": "nurse"},
    "break_glass": {"enabled": false},
    "tenant_id": "hospital-a",
    "purpose_of_use": "TREATMENT",
    "access_counts": {"last_minute": 1, "last_hour": 5, "last_day": 50},
    "is_after_hours": false
}

_breakglass_subject := {
    "has_roles": true,
    "roles": ["nurse", "can_break_glass"],
    "fhir_context": {"department": "ED", "role": "nurse"},
    "break_glass": {"enabled": true, "justification": "Code blue"},
    "tenant_id": "hospital-a",
    "purpose_of_use": "EMERGENCY",
    "access_counts": {"last_minute": 1, "last_hour": 5, "last_day": 50},
    "is_after_hours": false
}

# ─── $everything tests ─────────────────────────────────────

test_everything_denies_without_breakglass if {
    bulk_deny with input as {
        "subject": _nurse_subject,
        "resource": {"type": "Patient", "patient_id": "p1"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient/p1/$everything",
            "path_parts": ["Patient", "p1", "$everything"],
            "query": {}
        }
    }
}

test_everything_reason_without_breakglass if {
    reason == "bulk_everything_without_break_glass" with input as {
        "subject": _nurse_subject,
        "resource": {"type": "Patient", "patient_id": "p1"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient/p1/$everything",
            "path_parts": ["Patient", "p1", "$everything"],
            "query": {}
        }
    }
}

test_everything_allowed_with_breakglass if {
    not bulk_deny with input as {
        "subject": _breakglass_subject,
        "resource": {"type": "Patient", "patient_id": "p1"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient/p1/$everything",
            "path_parts": ["Patient", "p1", "$everything"],
            "query": {}
        }
    }
}

# ─── high _count tests ─────────────────────────────────────

test_high_count_denies_without_breakglass if {
    bulk_deny with input as {
        "subject": _nurse_subject,
        "resource": {"type": "Patient"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient",
            "path_parts": ["Patient"],
            "query": {"_count": "500"}
        }
    }
}

test_high_count_reason if {
    reason == "bulk_count_exceeded" with input as {
        "subject": _nurse_subject,
        "resource": {"type": "Patient"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient",
            "path_parts": ["Patient"],
            "query": {"_count": "500"}
        }
    }
}

test_low_count_not_denied if {
    not bulk_deny with input as {
        "subject": _nurse_subject,
        "resource": {"type": "Patient"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient",
            "path_parts": ["Patient"],
            "query": {"_count": "10"}
        }
    }
}

test_threshold_boundary_exactly_at_limit_not_denied if {
    not bulk_deny with input as {
        "subject": _nurse_subject,
        "resource": {"type": "Patient"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient",
            "path_parts": ["Patient"],
            "query": {"_count": "200"}
        }
    }
}

test_high_count_allowed_with_breakglass if {
    not bulk_deny with input as {
        "subject": _breakglass_subject,
        "resource": {"type": "Patient"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient",
            "path_parts": ["Patient"],
            "query": {"_count": "500"}
        }
    }
}

# ─── list operation warn tests ─────────────────────────────

test_list_operation_warns_not_denies if {
    bulk_warn with input as {
        "subject": _nurse_subject,
        "resource": {"type": "Patient"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient",
            "path_parts": ["Patient"],
            "query": {}
        }
    }
}

test_list_operation_not_denied if {
    not bulk_deny with input as {
        "subject": _nurse_subject,
        "resource": {"type": "Patient"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient",
            "path_parts": ["Patient"],
            "query": {}
        }
    }
}

test_list_operation_reason if {
    reason == "bulk_list_operation" with input as {
        "subject": _nurse_subject,
        "resource": {"type": "Patient"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient",
            "path_parts": ["Patient"],
            "query": {}
        }
    }
}

# Single resource read — no bulk signals
test_single_resource_no_bulk if {
    not bulk_deny with input as {
        "subject": _nurse_subject,
        "resource": {"type": "Patient", "patient_id": "p1"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient/p1",
            "path_parts": ["Patient", "p1"],
            "query": {}
        }
    }
}

test_single_resource_no_warn if {
    not bulk_warn with input as {
        "subject": _nurse_subject,
        "resource": {"type": "Patient", "patient_id": "p1"},
        "request": {
            "method": "GET",
            "path": "/fhir/r4/Patient/p1",
            "path_parts": ["Patient", "p1"],
            "query": {}
        }
    }
}
