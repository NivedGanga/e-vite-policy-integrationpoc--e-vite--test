package evite.restrict_customer_data_access_variant13

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"crm_agent", "sales_rep_1"}

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
    "actions": ["VIEW_CUSTOMER_DATA", "EXPORT_CUSTOMER_RECORDS"],
    "resources": [
        {"name": "CustomerRecord", "attributes": {"sensitivity": "high", "contains_pii": "true"}},
        {"name": "CrmDatabase", "attributes": {"region": "eu-central-1", "gdpr_scope": "true"}},
        {"name": "ExportManifest", "attributes": {"format": "csv", "destination": "s3"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.crm_role != null
    input.subject.attributes.crm_role == "intern"
    input.subject.attributes.gdpr_training_complete != null
    input.subject.attributes.gdpr_training_complete == "false"
    value_in_allowed(input.subject.attributes.restricted_data_categories, {"pii", "financial", "health"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some access_request in input.dependent_resources
    access_request.name == "DataAccessRequest"
    access_request.attributes.approved != "true"
    some purpose_limitation in input.dependent_resources
    purpose_limitation.name == "PurposeLimitation"
    purpose_limitation.attributes.declared_purpose == null
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
