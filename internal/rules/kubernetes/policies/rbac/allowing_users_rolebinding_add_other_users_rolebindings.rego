package builtin.kubernetes.KSV055

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV055",
	"avd_id": "AVD-KSV-0055",
	"title": "allowing users in a rolebinding to add other users to their rolebindings",
	"short_code": "view-all-secrets",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit allowing users in a rolebinding to add other users to their rolebindings",
	"recommended_actions": "create a Role which do not permit allowing users in a rolebinding to add other users to their rolebindings if not needed",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readKinds := ["Role", "ClusterRole"]

allowing_users_rolebinding_add_other_users_their_rolebindings {
	input.kind == readKinds[_]
	input.rules[_].apiGroups[_] == "*"
	input.rules[_].resources[_] == "rolebindings"
	input.rules[_].verbs[_] == "get"
	input.rules[_].verbs[_] == "patch"
}

deny[res] {
	allowing_users_rolebinding_add_other_users_their_rolebindings
	msg := "role permit allowing users in a rolebinding to add other users to their rolebindings"
	res := result.new(msg, input)
}
