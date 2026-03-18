package asidemenurestriction

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"User"}

deny if {
    subject_allowed
    dependencies_allowed
}

result := {
  "allow": not deny,
  "actions": ["Access"],
  "resources": [{"name":"Users Menu","attributes":{}},{"name":"Reports Menu","attributes":{}},{"name":"Rep Evites Menu","attributes":{}},{"name":"Rep Evite by Company Menu","attributes":{}},{"name":"Evites by Account Menu","attributes":{}}]
}

subject_allowed if {
  input.subject != null
  input.subject.attributes != null
  input.subject.attributes.userType != null
  input.subject.attributes.userType == "Basic"
  input.subject.name in allowed_subject_names
}

dependencies_allowed if { true }