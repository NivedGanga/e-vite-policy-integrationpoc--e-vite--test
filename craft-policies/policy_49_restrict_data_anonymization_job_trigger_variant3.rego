package evite.restrict_data_anonymization_job_trigger_variant3

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"privacy_engineer", "anonymization_svc"}

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
    "actions": ["TRIGGER_ANONYMIZATION_JOB", "VERIFY_ANONYMIZATION_OUTPUT"],
    "resources": [
        {"name": "AnonymizationJob", "attributes": {"technique": "k_anonymity", "dataset": "user_events"}},
        {"name": "PiiDataset", "attributes": {"classification": "sensitive", "rows_count": "10000000"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.privacy_role != null
    input.subject.attributes.privacy_role == "observer"
    input.subject.attributes.anonymization_tool_certified != null
    input.subject.attributes.anonymization_tool_certified == "false"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some legal_basis in input.dependent_resources
    legal_basis.name == "ProcessingLegalBasis"
    legal_basis.attributes.basis_type == null
    some data_inventory in input.dependent_resources
    data_inventory.name == "DataInventoryRecord"
    data_inventory.attributes.up_to_date != "true"
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
