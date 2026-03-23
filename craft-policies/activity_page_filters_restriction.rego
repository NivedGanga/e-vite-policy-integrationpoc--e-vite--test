package activity_page_filters_restriction

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
  "resources": [{"name":"Team Member Filter","attributes":{}}]
}

subject_allowed if {
  input.subject != null
  input.subject.attributes != null
  input.subject.name in allowed_subject_names
}

dependencies_allowed if { true }