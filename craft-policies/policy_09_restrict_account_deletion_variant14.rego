package evite.restrict_account_deletion_variant14

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"account_owner"}

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
    "actions": ["DELETE_ACCOUNT", "PURGE_DATA"],
    "resources": [
        {"name": "Account", "attributes": {"type": "enterprise", "protected": "true"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.account_age_days != null
    input.subject.attributes.account_age_days == "0"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some active_sub in input.dependent_resources
    active_sub.name == "ActiveSubscription"
    active_sub.attributes.plan != null
    active_sub.attributes.plan != "free"
    some pending_invoice in input.dependent_resources
    pending_invoice.name == "PendingInvoice"
    pending_invoice.attributes.amount_due != "0"
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
