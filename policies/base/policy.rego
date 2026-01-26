package firewall.decision

import future.keywords.if
import future.keywords.in

default allow := false
default remove := []
default mask := []

# Allow if user has roles
allow if {
    input.subject.has_roles
    input.subject.roles
    count(input.subject.roles) > 0
}

# Deny if no roles
allow := false if {
    not input.subject.has_roles
}

# Break-glass override
allow if {
    input.subject.break_glass.enabled
    "can_break_glass" in input.subject.roles
}

# Determine reason
reason := "no_roles" if {
    not input.subject.has_roles
}

reason := "authorized" if {
    allow
}

reason := "break_glass_access" if {
    input.subject.break_glass.enabled
}

# Final result
result := {
    "allow": allow,
    "remove": remove,
    "mask": mask,
    "reason": reason
}