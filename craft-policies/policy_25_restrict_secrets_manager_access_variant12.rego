package evite.restrict_secrets_manager_access_variant12

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"vault_reader", "app_service_x"}

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
    "actions": ["READ_SECRET", "WRITE_SECRET", "ROTATE_SECRET"],
    "resources": [
        {"name": "SecretsManager", "attributes": {"provider": "hashicorp_vault", "env": "production"}},
        {"name": "SecretEntry", "attributes": {"classification": "critical", "ttl": "never"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.vault_policy != null
    input.subject.attributes.vault_policy == "deny_all"
    input.subject.attributes.secret_scope != null
    input.subject.attributes.secret_scope == "global"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some break_glass in input.dependent_resources
    break_glass.name == "BreakGlassRequest"
    break_glass.attributes.active != "true"
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
