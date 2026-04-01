package evite.allow_user_profile_update_variant19

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"self_service_user", "profile_editor"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["UPDATE_PROFILE", "CHANGE_AVATAR", "UPDATE_PREFERENCES"],
    "resources": [
        {"name": "UserProfile", "attributes": {"owner": "self", "visibility": "public"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.account_verified != null
    input.subject.attributes.account_verified == "true"
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
