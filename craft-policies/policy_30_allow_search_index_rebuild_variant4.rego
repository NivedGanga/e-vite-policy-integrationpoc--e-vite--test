package evite.allow_search_index_rebuild_variant4

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"search_ops", "index_scheduler"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["REBUILD_INDEX", "REINDEX_COLLECTION"],
    "resources": [
        {"name": "SearchIndex", "attributes": {"engine": "elasticsearch", "env": "production"}},
        {"name": "DataCollection", "attributes": {"size_gb": "500", "type": "primary"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.search_admin != null
    input.subject.attributes.search_admin == "true"
    input.subject.attributes.off_peak_hours != null
    input.subject.attributes.off_peak_hours == "true"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some cluster_health in input.dependent_resources
    cluster_health.name == "ClusterHealth"
    cluster_health.attributes.status == "green"
    cluster_health.attributes.disk_usage_pct != null
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
