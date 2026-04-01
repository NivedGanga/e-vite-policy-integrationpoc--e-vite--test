package evite.allow_project_creation_variant4

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"carol", "dave", "erin"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["CREATE_PROJECT", "INITIALIZE_REPO"],
    "resources": [
        {"name": "Project", "attributes": {"type": "workspace", "tier": "pro"}},
        {"name": "Repository", "attributes": {"visibility": "private"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.subscription_tier != null
    input.subject.attributes.subscription_tier == "pro"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if { true }

is_array(arr) if {
    type_name(arr) == "array"
}

is_object(obj) if {
    type_name(obj) == "object"
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
