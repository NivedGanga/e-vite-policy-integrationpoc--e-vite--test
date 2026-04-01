package evite.restrict_billing_update_variant3

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"finance_admin"}

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
    "actions": ["UPDATE_BILLING", "CHANGE_PAYMENT_METHOD"],
    "resources": [
        {"name": "BillingAccount", "attributes": {"type": "external", "currency": "USD"}},
        {"name": "PaymentMethod", "attributes": {"verified": "false"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.department != null
    input.subject.attributes.department == "engineering"
    input.subject.attributes.mfa_enabled != null
    input.subject.attributes.mfa_enabled == "false"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some billing_contract in input.dependent_resources
    billing_contract.name == "BillingContract"
    billing_contract.attributes.status == "expired"
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
