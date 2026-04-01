package evite.restrict_org_settings_variant3

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"org_owner", "co_founder"}

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
    "actions": ["MODIFY_ORG_SETTINGS", "CHANGE_ORG_NAME", "UPDATE_LOGO"],
    "resources": [
        {"name": "OrgSettings", "attributes": {"locked": "true"}},
        {"name": "OrgProfile", "attributes": {"visibility": "public"}},
        {"name": "BrandAssets", "attributes": {"type": "logo"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.account_locked != null
    input.subject.attributes.account_locked == "true"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some compliance_hold in input.dependent_resources
    compliance_hold.name == "ComplianceHold"
    compliance_hold.attributes.active == "true"
    compliance_hold.attributes.reason != null
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
