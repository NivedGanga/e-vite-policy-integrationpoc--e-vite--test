package evite.restrict_partner_portal_access_variant20

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"partner_user_abc", "reseller_xyz"}

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
    "actions": ["ACCESS_PARTNER_PORTAL", "VIEW_DEAL_REGISTRATION"],
    "resources": [
        {"name": "PartnerPortal", "attributes": {"tier": "gold", "region": "emea"}},
        {"name": "DealRegistration", "attributes": {"status": "pending_approval"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.partner_status != null
    input.subject.attributes.partner_status == "inactive"
    input.subject.attributes.agreement_signed != null
    input.subject.attributes.agreement_signed == "false"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some partner_contract in input.dependent_resources
    partner_contract.name == "PartnerContract"
    partner_contract.attributes.expired == "true"
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
