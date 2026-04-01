package evite.allow_team_invite_variant7

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"team_lead_alpha", "team_lead_beta"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["INVITE_MEMBER", "ASSIGN_ROLE"],
    "resources": [{"name": "Team", "attributes": {"size_limit": "50", "type": "internal"}}]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.role != null
    input.subject.attributes.role == "team_lead"
    input.subject.attributes.verified_email != null
    input.subject.attributes.verified_email == "true"
    input.subject.attributes.org_tenure_years != null
    input.subject.attributes.org_tenure_years != "0"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some org in input.dependent_resources
    org.name == "Organization"
    org.attributes.invite_policy == "open"
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
