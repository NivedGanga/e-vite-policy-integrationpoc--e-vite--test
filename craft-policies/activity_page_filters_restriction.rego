package e_vite.policies.activity_page_filters_restriction

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
  "resources": [{"name":"Team Member Filter","attributes":{}}]
}

subject_allowed if {
  input.subject != null
  input.subject.attributes != null
  input.subject.attributes.userType != null
  input.subject.attributes.userType == "Admin"
  input.subject.name in allowed_subject_names
}

dependencies_allowed if { true }

policy_effect := "allow"
policy_state := "active"