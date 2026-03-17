package side_menu_for_basic

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
  "actions": ["View"],
  "resources": [{"name":"Preference Menu","attributes":{}},{"name":"Organization Menu","attributes":{}},{"name":"Accounts Menu","attributes":{}},{"name":"Activity Menu","attributes":{}},{"name":"Leaderboard Menu","attributes":{}},{"name":"Home Menu","attributes":{}},{"name":"ContactUs Menu","attributes":{}}]
}

subject_allowed if {
  input.subject != null
  input.subject.attributes != null
  input.subject.attributes.userType != null
  input.subject.attributes.userType == "Basic"
  input.subject.name in allowed_subject_names
}

dependencies_allowed if { true }