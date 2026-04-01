package evite.allow_enterprise_security_policy_enforcement_variant5

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"ciso_office", "security_policy_bot"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["ENFORCE_SECURITY_POLICY", "QUARANTINE_DEVICE", "REVOKE_ALL_SESSIONS"],
    "resources": [
        {"name": "SecurityPolicy", "attributes": {"framework": "iso27001", "scope": "enterprise"}},
        {"name": "EndpointDevice", "attributes": {"managed": "true", "os": "windows"}},
        {"name": "SessionStore", "attributes": {"type": "distributed", "env": "production"}},
        {"name": "IncidentRecord", "attributes": {"severity": "critical", "status": "active"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.security_role != null
    input.subject.attributes.security_role == "ciso"
    input.subject.attributes.incident_commander != null
    input.subject.attributes.incident_commander == "true"
    input.subject.attributes.mfa_verified != null
    input.subject.attributes.mfa_verified == "true"
    value_in_allowed(input.subject.attributes.authorized_frameworks, {"iso27001", "nist", "soc2"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some incident_ticket in input.dependent_resources
    incident_ticket.name == "IncidentTicket"
    incident_ticket.attributes.severity == "critical"
    incident_ticket.attributes.declared_by != null
    some board_notification in input.dependent_resources
    board_notification.name == "BoardNotification"
    board_notification.attributes.sent == "true"
    some legal_hold in input.dependent_resources
    legal_hold.name == "LegalHold"
    legal_hold.attributes.placed == "true"
    legal_hold.attributes.case_number != null
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
