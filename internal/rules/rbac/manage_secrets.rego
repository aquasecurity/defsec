package builtin.kubernetes.KSV041

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV041",
	"avd_id": "AVD-KSV-0041",
	"title": "Do not allow management of secrets",
	"short_code": "no-manage-secrets",
	"severity": "CRITICAL",
	"description": "Check whether role permits managing secrets",
	"recommended_actions": "Create a role which does not permit to manage secrets if not needed",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readVerbs := ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

resourceManageSecret[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "secrets"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := resourceManageSecret[_]
	msg := "Role permits management of secret(s)"
	res := result.new(msg, badRule)
}
