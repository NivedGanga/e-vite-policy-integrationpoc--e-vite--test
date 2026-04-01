package evite.allow_custom_domain_setup_variant11

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"domain_admin", "onboarding_svc"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["ADD_CUSTOM_DOMAIN", "VERIFY_DOMAIN_OWNERSHIP"],
    "resources": [
        {"name": "CustomDomain", "attributes": {"tld": "com", "ssl_provisioned": "false"}},
        {"name": "DomainVerification", "attributes": {"method": "dns_txt"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.plan_supports_custom_domain != null
    input.subject.attributes.plan_supports_custom_domain == "true"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some dns_check in input.dependent_resources
    dns_check.name == "DnsVerificationCheck"
    dns_check.attributes.propagated == "true"
    some ssl_provider in input.dependent_resources
    ssl_provider.name == "SslProvider"
    ssl_provider.attributes.available == "true"
    ssl_provider.attributes.quota_remaining != "0"
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
