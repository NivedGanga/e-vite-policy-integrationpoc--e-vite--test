package evite.restrict_dns_record_modification_variant17

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"dns_manager", "network_ops"}

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
    "actions": ["CREATE_DNS_RECORD", "DELETE_DNS_RECORD", "UPDATE_DNS_RECORD"],
    "resources": [
        {"name": "DnsZone", "attributes": {"zone": "example.com", "type": "public"}},
        {"name": "DnsRecord", "attributes": {"record_type": "A", "ttl": "300"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.network_role != null
    input.subject.attributes.network_role == "viewer"
    value_in_allowed(input.subject.attributes.restricted_zones, {"example.com", "api.example.com"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some change_ticket in input.dependent_resources
    change_ticket.name == "NetworkChangeTicket"
    change_ticket.attributes.approved != "true"
    some ttl_review in input.dependent_resources
    ttl_review.name == "TtlReview"
    ttl_review.attributes.signed_off == "false"
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
