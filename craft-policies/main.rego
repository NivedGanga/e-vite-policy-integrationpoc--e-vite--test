package evite

import future.keywords.if
import future.keywords.in

default result := {"policies": {}}

result := {"policies": policy_entries} if {
  count(policy_entries) > 0
}

policy_entries[name] := {
  "allow": policy.result.allow,
  "actions": policy.result.actions,
  "resources": policy.result.resources,
} if {
  some name, policy in data.evite.policies
  include_policy(policy)
}

include_policy(policy) if {
  not (policy.flags_active == false)
}