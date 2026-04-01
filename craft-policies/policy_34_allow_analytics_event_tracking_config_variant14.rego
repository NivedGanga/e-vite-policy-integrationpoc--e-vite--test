package evite.allow_analytics_event_tracking_config_variant14

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"growth_analyst", "analytics_admin"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["CONFIGURE_EVENT_TRACKING", "CREATE_FUNNEL"],
    "resources": [
        {"name": "AnalyticsPipeline", "attributes": {"provider": "mixpanel", "env": "production"}},
        {"name": "EventSchema", "attributes": {"version": "v2", "pii_fields": "none"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.analytics_role != null
    input.subject.attributes.analytics_role == "analyst"
    input.subject.attributes.data_privacy_certified != null
    input.subject.attributes.data_privacy_certified == "true"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if { true }

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
