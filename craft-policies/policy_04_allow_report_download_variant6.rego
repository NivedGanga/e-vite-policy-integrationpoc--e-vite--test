package evite.allow_report_download_variant6

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"analyst_1", "analyst_2", "report_viewer"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["DOWNLOAD_REPORT"],
    "resources": [{"name": "Report", "attributes": {"classification": "confidential", "format": "pdf"}}]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.clearance_level != null
    input.subject.attributes.clearance_level == "high"
    value_in_allowed(input.subject.attributes.allowed_report_types, {"financial", "operational", "compliance"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some approval in input.dependent_resources
    approval.name == "DownloadApproval"
    approval.attributes.approved_by != null
    approval.attributes.approved_by != ""
    some quota in input.dependent_resources
    quota.name == "DownloadQuota"
    quota.attributes.remaining != "0"
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
