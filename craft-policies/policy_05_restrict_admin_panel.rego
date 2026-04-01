package evite.restrict_admin_panel

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"super_admin", "sys_root"}

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
    "actions": ["ACCESS_ADMIN_PANEL"],
    "resources": [
        {"name": "AdminPanel", "attributes": {"env": "production", "risk_level": "critical"}},
        {"name": "SystemConfig", "attributes": {"editable": "true"}},
        {"name": "AuditLog", "attributes": {"retention_days": "90"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.role != null
    input.subject.attributes.role == "contractor"
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
