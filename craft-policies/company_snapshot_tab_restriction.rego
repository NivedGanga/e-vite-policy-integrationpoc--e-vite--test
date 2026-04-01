package e_vite.policies.company_snapshot_tab_restriction

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"User"}

allow if {
    subject_allowed
    dependencies_allowed
  }

result := {
  "allow": allow,
  "actions": ["Access"],
  "resources": [{"name":"Company All Time Snapshot","attributes":{}}]
}

subject_allowed if {
  input.subject != null
  input.subject.attributes != null
  input.subject.attributes.userType != null
  input.subject.attributes.userType == "Basic"
  input.subject.name in allowed_subject_names
}

dependencies_allowed if { true }

policy_effect := "allow"
policy_state := "active"