package e_vite_side_menu

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"E-Vite user"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
  "allow": allow,
  "actions": ["View"],
  "resources": [{"name":"Home","attributes":{}},{"name":"Leaderboard","attributes":{}},{"name":"Activity","attributes":{}},{"name":"Accounts","attributes":{}},{"name":"Settings","attributes":{}},{"name":"Settings-Organization","attributes":{}},{"name":"Settings-Preferences","attributes":{}},{"name":"Settings-ContactUs","attributes":{}},{"name":"Settings-Users","attributes":{}},{"name":"Reports","attributes":{}}]
}

subject_allowed if {
  input.subject != null
  input.subject.attributes != null
  input.subject.name in allowed_subject_names
}

dependencies_allowed if { true }