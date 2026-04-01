package evite.restrict_cloud_cost_anomaly_alert_config_variant7

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"finops_analyst", "cost_monitor_bot"}

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
    "actions": ["CONFIGURE_COST_ALERT", "DISABLE_COST_ALERT"],
    "resources": [
        {"name": "CostAnomalyAlert", "attributes": {"provider": "aws", "threshold_usd": "10000"}},
        {"name": "BudgetPolicy", "attributes": {"scope": "org_wide", "enforce": "true"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.finops_role != null
    input.subject.attributes.finops_role == "viewer"
    input.subject.attributes.budget_owner != null
    input.subject.attributes.budget_owner == "false"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some budget_approval in input.dependent_resources
    budget_approval.name == "BudgetApproval"
    budget_approval.attributes.sign_off != "true"
    some cost_center in input.dependent_resources
    cost_center.name == "CostCenter"
    cost_center.attributes.active == "false"
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
