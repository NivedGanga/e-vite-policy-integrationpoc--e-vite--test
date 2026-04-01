package evite.allow_workspace_creation_variant6

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"workspace_manager", "org_admin_ws"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["CREATE_WORKSPACE", "SET_WORKSPACE_POLICY"],
    "resources": [
        {"name": "Workspace", "attributes": {"type": "shared", "region": "ap-south-1"}},
        {"name": "WorkspacePolicy", "attributes": {"default_access": "restricted"}},
        {"name": "StorageQuota", "attributes": {"limit_gb": "100"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.org_role != null
    input.subject.attributes.org_role == "admin"
    input.subject.attributes.workspace_quota_remaining != null
    input.subject.attributes.workspace_quota_remaining != "0"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some org_plan in input.dependent_resources
    org_plan.name == "OrgPlan"
    org_plan.attributes.allows_workspaces == "true"
    org_plan.attributes.workspace_limit != "0"
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
