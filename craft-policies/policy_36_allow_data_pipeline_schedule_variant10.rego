package evite.allow_data_pipeline_schedule_variant10

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"pipeline_scheduler", "etl_admin"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["SCHEDULE_PIPELINE", "PAUSE_PIPELINE", "RESUME_PIPELINE"],
    "resources": [
        {"name": "DataPipeline", "attributes": {"type": "batch", "cadence": "daily"}},
        {"name": "PipelineScheduler", "attributes": {"timezone": "UTC", "max_concurrent_runs": "3"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.pipeline_role != null
    input.subject.attributes.pipeline_role == "scheduler"
    input.subject.attributes.pipeline_quota_ok != null
    input.subject.attributes.pipeline_quota_ok == "true"
    value_in_allowed(input.subject.attributes.allowed_pipeline_types, {"batch", "streaming", "micro_batch"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some resource_check in input.dependent_resources
    resource_check.name == "ComputeResourceCheck"
    resource_check.attributes.capacity_available == "true"
    some upstream_pipeline in input.dependent_resources
    upstream_pipeline.name == "UpstreamPipeline"
    upstream_pipeline.attributes.last_run_status == "success"
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
