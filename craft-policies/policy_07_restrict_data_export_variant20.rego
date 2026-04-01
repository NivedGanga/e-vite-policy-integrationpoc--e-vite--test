package evite.restrict_data_export_variant20

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"data_engineer_1"}

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
    "actions": ["EXPORT_DATA", "DOWNLOAD_BULK"],
    "resources": [
        {"name": "DataWarehouse", "attributes": {"region": "eu-west-1", "classification": "pii"}},
        {"name": "ExportJob", "attributes": {"format": "csv"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.gdpr_trained != null
    input.subject.attributes.gdpr_trained == "false"
    value_in_allowed(input.subject.attributes.allowed_regions, {"us-east-1", "ap-south-1"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some dpa in input.dependent_resources
    dpa.name == "DataProcessingAgreement"
    dpa.attributes.signed == "false"
    some export_window in input.dependent_resources
    export_window.name == "ExportWindow"
    export_window.attributes.is_open != "true"
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
