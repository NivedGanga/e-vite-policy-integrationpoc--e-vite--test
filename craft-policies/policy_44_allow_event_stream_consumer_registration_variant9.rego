package evite.allow_event_stream_consumer_registration_variant9

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"event_platform_svc", "kafka_admin"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["REGISTER_CONSUMER", "SET_CONSUMER_GROUP_OFFSET"],
    "resources": [
        {"name": "EventStream", "attributes": {"broker": "kafka", "topic": "orders.v2"}},
        {"name": "ConsumerGroup", "attributes": {"isolation_level": "read_committed"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.streaming_role != null
    input.subject.attributes.streaming_role == "consumer_admin"
    input.subject.attributes.schema_registry_access != null
    input.subject.attributes.schema_registry_access == "true"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some schema_check in input.dependent_resources
    schema_check.name == "SchemaCompatibilityCheck"
    schema_check.attributes.compatible == "true"
    schema_check.attributes.schema_version != null
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
