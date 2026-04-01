package evite.restrict_data_retention_policy_change_variant13

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"data_governance_lead", "compliance_bot"}

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
    "actions": ["UPDATE_RETENTION_POLICY", "DELETE_RETENTION_RULE"],
    "resources": [
        {"name": "DataRetentionPolicy", "attributes": {"classification": "regulated", "min_retention_years": "7"}},
        {"name": "RetentionRuleSet", "attributes": {"jurisdiction": "eu", "locked": "true"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.governance_role != null
    input.subject.attributes.governance_role == "associate"
    input.subject.attributes.legal_hold_awareness != null
    input.subject.attributes.legal_hold_awareness == "false"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some legal_review in input.dependent_resources
    legal_review.name == "LegalReview"
    legal_review.attributes.cleared != "true"
    some dpo_sign_off in input.dependent_resources
    dpo_sign_off.name == "DpoSignOff"
    dpo_sign_off.attributes.obtained == "false"
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
