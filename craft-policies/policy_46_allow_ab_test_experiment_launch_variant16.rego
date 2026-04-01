package evite.allow_ab_test_experiment_launch_variant16

import future.keywords.if
import future.keywords.in

default allow := false

allowed_subject_names = {"experimentation_lead", "growth_pm"}

allow if {
    subject_allowed
    dependencies_allowed
}

result := {
    "allow": allow,
    "actions": ["LAUNCH_EXPERIMENT", "SET_TRAFFIC_SPLIT", "CONCLUDE_EXPERIMENT"],
    "resources": [
        {"name": "AbExperiment", "attributes": {"type": "multivariate", "audience": "all_users"}},
        {"name": "ExperimentMetric", "attributes": {"primary_metric": "conversion_rate"}}
    ]
}

subject_allowed if {
    input.subject != null
    input.subject.attributes != null
    input.subject.attributes.experimentation_certified != null
    input.subject.attributes.experimentation_certified == "true"
    input.subject.attributes.experiments_running != null
    input.subject.attributes.experiments_running != "10"
    value_in_allowed(input.subject.attributes.allowed_audiences, {"all_users", "beta_users", "new_signups"})
    input.subject.name in allowed_subject_names
}

dependencies_allowed if {
    some power_analysis in input.dependent_resources
    power_analysis.name == "StatisticalPowerAnalysis"
    power_analysis.attributes.sample_size_sufficient == "true"
    some ethics_review in input.dependent_resources
    ethics_review.name == "ExperimentEthicsReview"
    ethics_review.attributes.cleared == "true"
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
