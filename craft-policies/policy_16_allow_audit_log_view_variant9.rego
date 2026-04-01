package evite.allow_audit_log_view_variant9

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"auditor_external", "compliance_officer"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["VIEW_AUDIT_LOG", "EXPORT_AUDIT_LOG"],
    "resources": [
        {"name": "AuditLog", "attributes": {"classification": "restricted", "retention_policy": "7_years"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.auditor_certified != null
    input.subject.attributes.auditor_certified == "true"
    input.subject.attributes.nda_signed != null
    input.subject.attributes.nda_signed == "true"
    value_in_allowed(input.subject.attributes.audit_scope, {"financial", "security", "privacy"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some engagement_letter in input.dependent_resources
    engagement_letter.name == "EngagementLetter"
    engagement_letter.attributes.signed == "true"
    engagement_letter.attributes.valid_until != null
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
