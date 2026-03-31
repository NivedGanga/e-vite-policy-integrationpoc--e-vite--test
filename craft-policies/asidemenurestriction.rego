package e_vite.policies.asidemenurestriction

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"User"}

deny if {
    subject_allowed
    dependencies_allowed
  }

default allow_result := true

allow_result := false if {
    deny
}

result := {
  "allow": allow_result,
  "actions": ["Access"],
  "resources": [{"name":"Rep Evites Menu","attributes":{}},{"name":"Invite User Menu","attributes":{}},{"name":"User Actions Menu","attributes":{}},{"name":"Rep Evite by Company Menu","attributes":{}},{"name":"Evites by Account Menu","attributes":{}},{"name":"Reports Menu","attributes":{}}]
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