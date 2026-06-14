package firewall.bulk_access

import future.keywords.if
import future.keywords.in

# ─── thresholds ────────────────────────────────────────────
# Requests asking for more than this many resources in one call
# are classified as bulk and require break-glass justification.
bulk_count_threshold := 200

# ─── helpers ───────────────────────────────────────────────

# $everything operations — return the entire patient record in one shot.
is_everything_operation if {
    endswith(input.request.path, "/$everything")
}

# List operation: no resource ID, returns a Bundle of many resources.
# e.g. GET /fhir/r4/Patient  (no ID segment)
is_list_operation if {
    count(input.request.path_parts) == 1
    input.request.method == "GET"
}

# Explicit high-count query parameter.
has_high_count if {
    count_str := input.request.query["_count"]
    count_val := to_number(count_str)
    count_val > bulk_count_threshold
}

# ─── bulk_deny ─────────────────────────────────────────────
# bulk_deny blocks the request when a large-volume operation is
# attempted without break-glass. authz.rego imports this and
# combines it with the standard allow rules.

default bulk_deny := false

bulk_deny if {
    is_everything_operation
    not input.subject.break_glass.enabled
}

bulk_deny if {
    has_high_count
    not input.subject.break_glass.enabled
}

# ─── bulk_warn ─────────────────────────────────────────────
# bulk_warn is non-blocking — recorded in the audit reason for
# Privacy Officer dashboards, does not reject the request.

default bulk_warn := false

bulk_warn if {
    is_list_operation
    not is_everything_operation
}

# ─── reason ────────────────────────────────────────────────
default reason := ""

reason := "bulk_everything_without_break_glass" if {
    bulk_deny
    is_everything_operation
}

reason := "bulk_count_exceeded" if {
    bulk_deny
    has_high_count
    not is_everything_operation
}

reason := "bulk_list_operation" if {
    bulk_warn
    not bulk_deny
}

# ─── result ────────────────────────────────────────────────
result := {
    "bulk_deny": bulk_deny,
    "bulk_warn": bulk_warn,
    "reason":    reason,
}
