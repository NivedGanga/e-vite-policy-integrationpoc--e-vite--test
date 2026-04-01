package evite.allow_service_account_creation_variant7

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"platform_engineer", "iam_provisioner"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["CREATE_SERVICE_ACCOUNT", "ATTACH_SERVICE_ACCOUNT_POLICY"],
    "resources": [
        {"name": "ServiceAccount", "attributes": {"scope": "project", "env": "production"}},
        {"name": "IamBinding", "attributes": {"role": "custom", "level": "project"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.iam_certified != null
    input.subject.attributes.iam_certified == "true"
    input.subject.attributes.platform_role != null
    input.subject.attributes.platform_role == "engineer"
    value_in_allowed(input.subject.attributes.allowed_scopes, {"project", "folder"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some naming_policy in input.dependent_resources
    naming_policy.name == "ServiceAccountNamingPolicy"
    naming_policy.attributes.compliant == "true"
    some least_privilege_review in input.dependent_resources
    least_privilege_review.name == "LeastPrivilegeReview"
    least_privilege_review.attributes.approved == "true"
    least_privilege_review.attributes.reviewer != null
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
