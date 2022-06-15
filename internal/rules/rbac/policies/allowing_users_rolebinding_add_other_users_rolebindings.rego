package builtin.kubernetes.KSV055

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV055",
	"avd_id": "AVD-KSV-0055",
	"title": "Do not allow users in a rolebinding to add other users to their rolebindings",
	"short_code": "view-all-secrets",
	"severity": "LOW",
	"description": "Check whether role permits allowing users in a rolebinding to add other users to their rolebindings",
	"recommended_actions": "Create a role which does not permit allowing users in a rolebinding to add other users to their rolebindings if not needed",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readKinds := ["Role", "ClusterRole"]

allowing_users_rolebinding_add_other_users_their_rolebindings[input.rules[ru]] {
	some ru
	input.kind == readKinds[_]
	input.rules[ru].apiGroups[_] == "*"
	input.rules[ru].resources[_] == "rolebindings"
	input.rules[ru].verbs[_] == "get"
	input.rules[ru].verbs[_] == "patch"
}

deny[res] {
	badRule := allowing_users_rolebinding_add_other_users_their_rolebindings[_]
	msg := "Role permits allowing users in a rolebinding to add other users to their rolebindings"
	res := result.new(msg, badRule)
}
