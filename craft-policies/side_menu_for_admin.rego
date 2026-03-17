package side_menu_for_admin

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
  "resources": [{"name":"Users Menu","attributes":{}},{"name":"Reports Menu","attributes":{}},{"name":"Settings Menu","attributes":{}},{"name":"Accounts Menu","attributes":{}},{"name":"Activity Menu","attributes":{}},{"name":"Leaderboard Menu","attributes":{}},{"name":"Home Menu","attributes":{}},{"name":"ContactUs Menu","attributes":{}},{"name":"Rep Evites Menu","attributes":{}},{"name":"Rep Evite by Company Menu","attributes":{}},{"name":"Evites by Account Menu","attributes":{}}]
}

subject_allowed if {
  input.subject != null
  input.subject.attributes != null
  input.subject.attributes.userType != null
  input.subject.attributes.userType == "Admin"
  input.subject.name in allowed_subject_names
}

dependencies_allowed if { true }