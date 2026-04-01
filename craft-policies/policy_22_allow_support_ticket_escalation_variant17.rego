package evite.allow_support_ticket_escalation_variant17

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"support_agent_1", "support_agent_2", "support_agent_3"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["ESCALATE_TICKET", "REASSIGN_TICKET"],
    "resources": [
        {"name": "SupportTicket", "attributes": {"priority": "high", "category": "billing"}},
        {"name": "EscalationQueue", "attributes": {"tier": "2"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.support_level != null
    input.subject.attributes.support_level == "tier1"
    input.subject.attributes.tickets_resolved_today != null
    input.subject.attributes.tickets_resolved_today != "0"
    value_in_allowed(input.subject.attributes.certified_categories, {"billing", "technical", "account"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some ticket_history in input.dependent_resources
    ticket_history.name == "TicketHistory"
    ticket_history.attributes.unresolved_attempts != null
    ticket_history.attributes.unresolved_attempts != "0"
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
