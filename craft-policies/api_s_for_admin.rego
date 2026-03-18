package api_s_for_admin

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
  "resources": [{"name":"app/users/inviteuser","attributes":{}},{"name":"app/users/authorizeUsers","attributes":{}},{"name":"app/users/adminupdateuser","attributes":{}},{"name":"app/users/getrequestedcount","attributes":{}}]
}

subject_allowed if {
  input.subject != null
  input.subject.attributes != null
  input.subject.attributes.userType != null
  input.subject.attributes.userType == "Admin"
  input.subject.name in allowed_subject_names
}

dependencies_allowed if { true }