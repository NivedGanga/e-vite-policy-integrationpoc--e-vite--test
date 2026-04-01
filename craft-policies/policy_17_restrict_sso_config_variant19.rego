package evite.restrict_sso_config_variant19

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"it_admin", "identity_manager"}

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
    "actions": ["CONFIGURE_SSO", "ENABLE_SAML"],
    "resources": [
        {"name": "SsoConfiguration", "attributes": {"protocol": "saml2", "env": "production"}},
        {"name": "IdentityProvider", "attributes": {"type": "external"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.it_role != null
    input.subject.attributes.it_role == "helpdesk"
    input.subject.attributes.privileged_access != null
    input.subject.attributes.privileged_access == "false"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some idp_contract in input.dependent_resources
    idp_contract.name == "IdpContract"
    idp_contract.attributes.verified == "false"
    some security_review in input.dependent_resources
    security_review.name == "SecurityReview"
    security_review.attributes.outcome != "approved"
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
