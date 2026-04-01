package evite.restrict_api_key_generation_variant14

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"dev_portal_user", "sdk_tester"}

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
    "actions": ["GENERATE_API_KEY"],
    "resources": [
        {"name": "ApiKey", "attributes": {"scope": "read_write", "expiry": "never"}},
        {"name": "DeveloperApp", "attributes": {"env": "production"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.account_type != null
    input.subject.attributes.account_type == "free_trial"
    value_in_allowed(input.subject.attributes.flagged_activities, {"excessive_requests", "scraping"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some key_quota in input.dependent_resources
    key_quota.name == "ApiKeyQuota"
    key_quota.attributes.keys_used != null
    key_quota.attributes.keys_used == key_quota.attributes.keys_limit
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
