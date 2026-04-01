package evite.allow_infrastructure_scaling_variant15

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"autoscaler_bot", "sre_oncall"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["SCALE_UP", "SCALE_DOWN", "RESIZE_NODE_POOL"],
    "resources": [
        {"name": "ComputeCluster", "attributes": {"provider": "gke", "env": "production"}},
        {"name": "NodePool", "attributes": {"machine_type": "n2-standard-8", "min_nodes": "3"}},
        {"name": "ScalingPolicy", "attributes": {"strategy": "target_cpu_utilization"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.sre_level != null
    input.subject.attributes.sre_level == "senior"
    input.subject.attributes.on_call_active != null
    input.subject.attributes.on_call_active == "true"
    value_in_allowed(input.subject.attributes.allowed_clusters, {"prod-us", "prod-eu", "prod-apac"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some load_metric in input.dependent_resources
    load_metric.name == "LoadMetric"
    load_metric.attributes.above_threshold == "true"
    load_metric.attributes.sustained_minutes != null
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
