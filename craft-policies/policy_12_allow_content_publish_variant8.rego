package evite.allow_content_publish_variant8

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"content_editor_A", "content_editor_B", "chief_editor"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["PUBLISH_CONTENT", "SCHEDULE_POST"],
    "resources": [
        {"name": "CmsContent", "attributes": {"channel": "web", "status": "draft"}},
        {"name": "PublishQueue", "attributes": {"priority": "normal"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.editor_level != null
    input.subject.attributes.editor_level == "senior"
    input.subject.attributes.content_approved != null
    input.subject.attributes.content_approved == "true"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some review in input.dependent_resources
    review.name == "ContentReview"
    review.attributes.review_status == "passed"
    review.attributes.reviewer != null
    some seo_check in input.dependent_resources
    seo_check.name == "SeoCheck"
    seo_check.attributes.score != "fail"
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
