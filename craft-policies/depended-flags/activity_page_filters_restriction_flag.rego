package e_vite.policies.activity_page_filters_restriction

import future.keywords.if
import future.keywords.in

default flags_active := false

feature_flags := [
  {"name": "enable_ca_free_users", "is_enabled": true},
  {"name": "enable_sso", "is_enabled": true},
]

flags_active := true if {
  count([f | f := feature_flags[_]; f.is_enabled]) == count(feature_flags)
}
