package evite.restrict_feature_flag_toggle_variant11

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"product_manager_1", "release_bot"}

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
    "actions": ["TOGGLE_FEATURE_FLAG"],
    "resources": [
        {"name": "FeatureFlag", "attributes": {"env": "production", "rollout_type": "percentage"}},
        {"name": "FeatureFlagAudit", "attributes": {"required": "true"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.pm_level != null
    input.subject.attributes.pm_level == "associate"
    value_in_allowed(input.subject.attributes.restricted_envs, {"production", "staging"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some change_request in input.dependent_resources
    change_request.name == "ChangeRequest"
    change_request.attributes.approved != "true"
    some rollout_plan in input.dependent_resources
    rollout_plan.name == "RolloutPlan"
    rollout_plan.attributes.tested == "false"
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
