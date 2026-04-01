package evite.restrict_database_backup_variant7

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"db_admin", "backup_service"}

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
    "actions": ["TRIGGER_BACKUP", "RESTORE_BACKUP"],
    "resources": [
        {"name": "Database", "attributes": {"engine": "postgres", "env": "production"}},
        {"name": "BackupStorage", "attributes": {"region": "us-west-2", "encrypted": "true"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.db_role != null
    input.subject.attributes.db_role == "reader"
    input.subject.attributes.on_call != null
    input.subject.attributes.on_call == "false"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some maintenance_window in input.dependent_resources
    maintenance_window.name == "MaintenanceWindow"
    maintenance_window.attributes.active == "false"
    some backup_policy in input.dependent_resources
    backup_policy.name == "BackupPolicy"
    backup_policy.attributes.approved != "true"
}

is_array(arr) if {
    type_name(arr) == "array"
}

is_object(obj) if {
    type_name(obj) == "object"
}

is_boolean(val) if {
    val == true
}

is_boolean(val) if {
    val == false
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
