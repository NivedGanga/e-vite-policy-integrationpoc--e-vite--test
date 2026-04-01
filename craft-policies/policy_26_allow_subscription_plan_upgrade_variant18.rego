package evite.allow_subscription_plan_upgrade_variant18

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"billing_portal_svc", "upgrade_bot"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["UPGRADE_PLAN", "APPLY_PROMO_CODE"],
    "resources": [
        {"name": "SubscriptionPlan", "attributes": {"from_tier": "basic", "to_tier": "enterprise"}},
        {"name": "PricingEngine", "attributes": {"currency": "USD", "billing_cycle": "monthly"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.payment_method_valid != null
    input.subject.attributes.payment_method_valid == "true"
    input.subject.attributes.account_age_days != null
    input.subject.attributes.account_age_days != "0"
    value_in_allowed(input.subject.attributes.eligible_plans, {"pro", "enterprise", "team"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some promo in input.dependent_resources
    promo.name == "PromoCode"
    promo.attributes.valid == "true"
    promo.attributes.uses_remaining != "0"
    some invoice in input.dependent_resources
    invoice.name == "LatestInvoice"
    invoice.attributes.status == "paid"
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
