package evite.allow_role_assignment_variant5

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"hr_manager", "access_admin"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["ASSIGN_ROLE", "REVOKE_ROLE"],
    "resources": [
        {"name": "UserRole", "attributes": {"scope": "organization"}},
        {"name": "PermissionGroup", "attributes": {"level": "standard"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.hr_clearance != null
    input.subject.attributes.hr_clearance == "level2"
    input.subject.attributes.active_session != null
    input.subject.attributes.active_session == "true"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some approval_ticket in input.dependent_resources
    approval_ticket.name == "ApprovalTicket"
    approval_ticket.attributes.ticket_status == "approved"
    approval_ticket.attributes.approver != null
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
