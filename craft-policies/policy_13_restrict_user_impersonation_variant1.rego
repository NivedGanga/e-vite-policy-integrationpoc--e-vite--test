package evite.restrict_user_impersonation_variant1

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"support_lead"}

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
    "actions": ["IMPERSONATE_USER"],
    "resources": [
        {"name": "ImpersonationSession", "attributes": {"target_tier": "enterprise", "duration_minutes": "60"}},
        {"name": "TargetAccount", "attributes": {"type": "external"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.support_tier != null
    input.subject.attributes.support_tier == "tier1"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some impersonation_log in input.dependent_resources
    impersonation_log.name == "ImpersonationLog"
    impersonation_log.attributes.consent_given == "false"
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
