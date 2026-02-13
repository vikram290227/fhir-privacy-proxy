package firewall.decision

import data.authz

# Re-export the authz decision so legacy queries to
# /v1/data/firewall/decision still work.
allow := authz.decision.allow
remove := authz.decision.remove
mask := authz.decision.mask
reason := authz.decision.reason

result := authz.decision
