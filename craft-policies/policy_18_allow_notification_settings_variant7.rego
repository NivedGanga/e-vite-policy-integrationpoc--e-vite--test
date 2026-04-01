package evite.allow_notification_settings_variant7

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"notif_admin", "platform_ops"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["UPDATE_NOTIFICATION_SETTINGS", "SEND_BULK_NOTIFICATION"],
    "resources": [
        {"name": "NotificationChannel", "attributes": {"type": "email", "provider": "sendgrid"}},
        {"name": "NotificationTemplate", "attributes": {"category": "transactional"}},
        {"name": "RecipientList", "attributes": {"size": "large"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.can_send_bulk != null
    input.subject.attributes.can_send_bulk == "true"
    input.subject.attributes.spam_score != null
    input.subject.attributes.spam_score == "low"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some unsubscribe_list in input.dependent_resources
    unsubscribe_list.name == "UnsubscribeList"
    unsubscribe_list.attributes.applied == "true"
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
