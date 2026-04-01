package evite.restrict_log_stream_access_variant17

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"log_consumer_svc", "observability_agent"}

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
    "actions": ["STREAM_LOGS", "FILTER_LOGS"],
    "resources": [
        {"name": "LogStream", "attributes": {"level": "debug", "env": "production", "contains_pii": "true"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.log_access_level != null
    input.subject.attributes.log_access_level == "none"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some pii_policy in input.dependent_resources
    pii_policy.name == "PiiAccessPolicy"
    pii_policy.attributes.granted == "false"
    some data_masking in input.dependent_resources
    data_masking.name == "DataMaskingConfig"
    data_masking.attributes.enabled != "true"
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
