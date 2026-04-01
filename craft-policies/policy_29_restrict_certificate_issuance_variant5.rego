package evite.restrict_certificate_issuance_variant5

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"pki_operator", "cert_bot"}

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
    "actions": ["ISSUE_CERTIFICATE", "REVOKE_CERTIFICATE"],
    "resources": [
        {"name": "Certificate", "attributes": {"type": "wildcard", "validity_days": "365"}},
        {"name": "CertificateAuthority", "attributes": {"root": "true", "env": "production"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.pki_role != null
    input.subject.attributes.pki_role == "requester"
    input.subject.attributes.domain_validated != null
    input.subject.attributes.domain_validated == "false"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some csr in input.dependent_resources
    csr.name == "CertificateSigningRequest"
    csr.attributes.reviewed != "true"
    some ca_policy in input.dependent_resources
    ca_policy.name == "CaIssuancePolicy"
    ca_policy.attributes.wildcard_allowed == "false"
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
