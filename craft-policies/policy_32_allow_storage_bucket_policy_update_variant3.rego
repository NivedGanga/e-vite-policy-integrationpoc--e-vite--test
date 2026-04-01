package evite.allow_storage_bucket_policy_update_variant3

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"storage_admin", "cloud_infra_bot"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["UPDATE_BUCKET_POLICY", "SET_BUCKET_ACL"],
    "resources": [
        {"name": "StorageBucket", "attributes": {"provider": "gcs", "public_access": "blocked"}},
        {"name": "BucketAcl", "attributes": {"scope": "org_wide"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.cloud_role != null
    input.subject.attributes.cloud_role == "storage_admin"
    input.subject.attributes.mfa_verified != null
    input.subject.attributes.mfa_verified == "true"
    value_in_allowed(input.subject.attributes.allowed_buckets, {"data-lake", "model-artifacts", "raw-ingestion"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some policy_review in input.dependent_resources
    policy_review.name == "PolicyReview"
    policy_review.attributes.status == "approved"
    policy_review.attributes.reviewed_by != null
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
