package evite.restrict_third_party_oauth_app_approval_variant5

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"oauth_reviewer", "app_marketplace_admin"}

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
    "actions": ["APPROVE_OAUTH_APP", "PUBLISH_TO_MARKETPLACE"],
    "resources": [
        {"name": "OauthApp", "attributes": {"scopes_requested": "admin", "verified_publisher": "false"}},
        {"name": "AppMarketplace", "attributes": {"visibility": "public", "category": "productivity"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.review_role != null
    input.subject.attributes.review_role == "junior_reviewer"
    value_in_allowed(input.subject.attributes.flagged_scope_types, {"admin", "write_all", "delete_all"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some security_scan in input.dependent_resources
    security_scan.name == "AppSecurityScan"
    security_scan.attributes.passed != "true"
    some privacy_review in input.dependent_resources
    privacy_review.name == "PrivacyReview"
    privacy_review.attributes.data_handling_approved == "false"
    some publisher_check in input.dependent_resources
    publisher_check.name == "PublisherVerification"
    publisher_check.attributes.identity_verified == "false"
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
