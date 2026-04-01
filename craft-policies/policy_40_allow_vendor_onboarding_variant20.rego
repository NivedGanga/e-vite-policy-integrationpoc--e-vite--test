package evite.allow_vendor_onboarding_variant20

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"procurement_lead", "vendor_ops"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["ONBOARD_VENDOR", "ASSIGN_VENDOR_CONTRACT"],
    "resources": [
        {"name": "VendorProfile", "attributes": {"category": "saas", "risk_tier": "low"}},
        {"name": "VendorContract", "attributes": {"type": "annual", "auto_renew": "false"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.procurement_level != null
    input.subject.attributes.procurement_level == "senior"
    input.subject.attributes.budget_authority != null
    input.subject.attributes.budget_authority == "true"
    value_in_allowed(input.subject.attributes.approved_vendor_categories, {"saas", "hardware", "consulting"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some due_diligence in input.dependent_resources
    due_diligence.name == "VendorDueDiligence"
    due_diligence.attributes.completed == "true"
    due_diligence.attributes.risk_accepted == "true"
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
