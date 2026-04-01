package evite.allow_payment_processing_variant6

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"payment_gateway_svc", "checkout_bot"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["PROCESS_PAYMENT", "ISSUE_REFUND", "CAPTURE_CHARGE"],
    "resources": [
        {"name": "PaymentGateway", "attributes": {"provider": "stripe", "mode": "live"}},
        {"name": "Transaction", "attributes": {"currency": "USD", "type": "charge"}},
        {"name": "CustomerWallet", "attributes": {"verified": "true"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.pci_compliant != null
    input.subject.attributes.pci_compliant == "true"
    input.subject.attributes.service_account != null
    input.subject.attributes.service_account == "true"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some fraud_check in input.dependent_resources
    fraud_check.name == "FraudCheck"
    fraud_check.attributes.risk_score != null
    fraud_check.attributes.risk_score == "low"
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
