package evite.restrict_pipeline_deploy_variant18

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"ci_bot", "deploy_svc"}

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
    "actions": ["DEPLOY_PIPELINE", "ROLLBACK_PIPELINE"],
    "resources": [
        {"name": "Pipeline", "attributes": {"env": "production", "strategy": "blue_green"}},
        {"name": "DeployTarget", "attributes": {"cluster": "k8s-prod", "namespace": "default"}},
        {"name": "ArtifactRegistry", "attributes": {"type": "docker", "verified": "true"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.deploy_role != null
    input.subject.attributes.deploy_role == "observer"
    value_in_allowed(input.subject.attributes.blocked_envs, {"production", "staging"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some test_suite in input.dependent_resources
    test_suite.name == "TestSuite"
    test_suite.attributes.passed != "true"
    some change_freeze in input.dependent_resources
    change_freeze.name == "ChangeFreezeWindow"
    change_freeze.attributes.active == "true"
    some approval in input.dependent_resources
    approval.name == "DeployApproval"
    approval.attributes.sign_off_count == "0"
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
