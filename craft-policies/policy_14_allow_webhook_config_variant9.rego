package evite.allow_webhook_config_variant9

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"integration_admin", "devops_lead"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["CREATE_WEBHOOK", "UPDATE_WEBHOOK", "DELETE_WEBHOOK"],
    "resources": [
        {"name": "Webhook", "attributes": {"protocol": "https", "retry_policy": "exponential"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.role != null
    input.subject.attributes.role == "integration_admin"
    input.subject.attributes.ip_whitelisted != null
    input.subject.attributes.ip_whitelisted == "true"
    value_in_allowed(input.subject.attributes.allowed_environments, {"staging", "production"})
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
