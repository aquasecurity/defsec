package builtin.kubernetes.KSV046

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV046",
	"avd_id": "AVD-KSV-0046",
	"title": "No wildcard resource roles",
	"short_code": "no-wildcard-resource-role",
	"severity": "CRITICAL",
	"description": "Check whether role permits specific verb on wildcard resources",
	"recommended_actions": "Create a role which does not permit specific verb on wildcard resources",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readVerbs := ["create", "update", "delete", "deletecollection", "impersonate", "*", "list", "get"]

readKinds := ["Role", "ClusterRole"]

resourceAllowSpecificVerbOnAnyResource[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "*"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := resourceAllowSpecificVerbOnAnyResource[_]
	msg := "Role permits specific verb on wildcard resource"
	res := result.new(msg, badRule)
}
