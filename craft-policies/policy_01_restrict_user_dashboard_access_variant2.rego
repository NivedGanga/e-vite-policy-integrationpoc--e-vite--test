package evite.restrict_user_dashboard_access_variant2

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"alice", "bob"}

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
    "actions": ["VIEW_DASHBOARD"],
    "resources": [{"name": "Dashboard", "attributes": {"type": "internal", "visibility": "private"}}]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.role != null
    input.subject.attributes.role == "viewer"
    input.subject.attributes.account_status != null
    input.subject.attributes.account_status == "suspended"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some session in input.dependent_resources
    session.name == "UserSession"
    session.attributes.is_active == false
}

is_array(arr) if {
    type_name(arr) == "array"
}

is_object(obj) if {
    type_name(obj) == "object"
}

is_boolean(val) if {
    val == true
}

is_boolean(val) if {
    val == false
}

value_in_allowed(val, allowed) if {
    val != null
    val in allowed
}

value_in_allowed(val, allowed) if {
    val != null
    is_array(val)
    count(val) > 0
    some i
    val[i] != null
    val[i] in allowed
}
