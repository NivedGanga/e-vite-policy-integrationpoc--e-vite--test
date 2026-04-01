package evite.allow_environment_provisioning_variant11

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"infra_engineer", "cloud_ops_lead"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["PROVISION_ENVIRONMENT", "DEPLOY_STACK", "CONFIGURE_NETWORK"],
    "resources": [
        {"name": "CloudEnvironment", "attributes": {"provider": "aws", "region": "us-east-1", "tier": "production"}},
        {"name": "NetworkConfig", "attributes": {"type": "vpc", "cidr": "10.0.0.0/16"}},
        {"name": "IamPolicy", "attributes": {"scope": "full_access"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.cloud_certified != null
    input.subject.attributes.cloud_certified == "true"
    input.subject.attributes.infra_role != null
    input.subject.attributes.infra_role == "engineer"
    input.subject.attributes.vpn_connected != null
    input.subject.attributes.vpn_connected == "true"
    value_in_allowed(input.subject.attributes.approved_regions, {"us-east-1", "eu-west-1", "ap-south-1"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some infra_ticket in input.dependent_resources
    infra_ticket.name == "InfraTicket"
    infra_ticket.attributes.approved == "true"
    infra_ticket.attributes.approved_by != null
    some cost_estimate in input.dependent_resources
    cost_estimate.name == "CostEstimate"
    cost_estimate.attributes.reviewed == "true"
    cost_estimate.attributes.budget_code != null
    some security_baseline in input.dependent_resources
    security_baseline.name == "SecurityBaseline"
    security_baseline.attributes.compliant == "true"
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
