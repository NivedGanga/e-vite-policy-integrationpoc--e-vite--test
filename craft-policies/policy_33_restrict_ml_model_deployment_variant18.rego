package evite.restrict_ml_model_deployment_variant18

import future.keywords.if
import future.keywords.in

default deny := false

allowed_subject_names = {"ml_engineer_1", "model_registry_bot"}

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
    "actions": ["DEPLOY_MODEL", "PROMOTE_MODEL_TO_PROD"],
    "resources": [
        {"name": "MlModel", "attributes": {"framework": "pytorch", "stage": "staging"}},
        {"name": "InferenceEndpoint", "attributes": {"env": "production", "autoscaling": "enabled"}},
        {"name": "ModelRegistry", "attributes": {"version_controlled": "true"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.ml_role != null
    input.subject.attributes.ml_role == "intern"
    input.subject.attributes.model_governance_trained != null
    input.subject.attributes.model_governance_trained == "false"
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some eval_report in input.dependent_resources
    eval_report.name == "ModelEvalReport"
    eval_report.attributes.passed_threshold != "true"
    some bias_check in input.dependent_resources
    bias_check.name == "BiasAudit"
    bias_check.attributes.completed == "false"
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
