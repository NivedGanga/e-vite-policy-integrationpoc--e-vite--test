package e_vite.policies.activity_page_filters_restriction

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"User"}

allow if {
    subject_allowed
    dependencies_allowed
  }

default allow_result := true

allow_result := allow

result := {
  "allow": allow_result,
  "actions": ["Access"],
  "resources": [{"name":"Team Member Filter","attributes":{}}]
}

subject_allowed if {
  input.subject != null
  input.subject.attributes != null
  input.subject.attributes.userType != null
  input.subject.attributes.userType == "Basic"
  input.subject.name in allowed_subject_names
}

dependencies_allowed if { true }

policy_effect := "deny"
policy_state := "active"