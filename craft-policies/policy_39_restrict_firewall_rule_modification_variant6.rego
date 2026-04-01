package evite.restrict_firewall_rule_modification_variant6

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"firewall_admin", "secops_engineer"}

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
    "actions": ["ADD_FIREWALL_RULE", "DELETE_FIREWALL_RULE", "MODIFY_FIREWALL_RULE"],
    "resources": [
        {"name": "FirewallRuleset", "attributes": {"env": "production", "criticality": "high"}},
        {"name": "FirewallRule", "attributes": {"direction": "inbound", "protocol": "tcp"}},
        {"name": "NetworkSegment", "attributes": {"zone": "dmz"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.network_clearance != null
    input.subject.attributes.network_clearance == "basic"
    input.subject.attributes.change_window_active != null
    input.subject.attributes.change_window_active == "false"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some risk_assessment in input.dependent_resources
    risk_assessment.name == "RiskAssessment"
    risk_assessment.attributes.risk_level == "critical"
    some peer_review in input.dependent_resources
    peer_review.name == "PeerReview"
    peer_review.attributes.approved != "true"
    some rollback_plan in input.dependent_resources
    rollback_plan.name == "RollbackPlan"
    rollback_plan.attributes.documented == "false"
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
