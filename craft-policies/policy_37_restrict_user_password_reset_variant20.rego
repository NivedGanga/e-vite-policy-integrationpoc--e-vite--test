package evite.restrict_user_password_reset_variant20

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"identity_svc", "auth_bot"}

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
    "actions": ["RESET_PASSWORD", "FORCE_LOGOUT_ALL_SESSIONS"],
    "resources": [
        {"name": "UserCredential", "attributes": {"auth_method": "password", "last_reset_days": "0"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.reset_origin != null
    input.subject.attributes.reset_origin == "unverified_email"
    input.subject.attributes.rate_limit_hit != null
    input.subject.attributes.rate_limit_hit == "true"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some token in input.dependent_resources
    token.name == "ResetToken"
    token.attributes.expired == "true"
}

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
