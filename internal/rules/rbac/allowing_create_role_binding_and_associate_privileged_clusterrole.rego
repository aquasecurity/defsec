package builtin.kubernetes.KSV051

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV051",
	"avd_id": "AVD-KSV-0051",
	"title": "Do not allow role binding creation and association with privileged role/clusterrole",
	"short_code": "do-not-allow-role-binding-associate-privileged-role",
	"severity": "HIGH",
	"description": "Check whether role permits creating role bindings and associating to privileged role/clusterrole",
	"recommended_actions": "Create a role which does not permit creation of role bindings and associating with privileged cluster role",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readKinds := ["Role", "ClusterRole"]

allowing_create_role_binding_and_associate_cluster_role {
	input.kind == readKinds[_]
	input.rules[_].apiGroups[_] == "rbac.authorization.k8s.io"
	input.rules[_].resources[_] == "rolebindings"
	input.rules[_].verbs[_] == "create"
	input.rules[_].apiGroups[_] == "rbac.authorization.k8s.io"
	input.rules[_].resources[_] == ["clusterroles", "roles"][_]
	input.rules[_].verbs[_] == "bind"
	input.rules[_].resourceNames[_] == "*"
}

deny[res] {
	allowing_create_role_binding_and_associate_cluster_role
	msg := "Role permits creation of role binding and association with privileged role"
	res := result.new(msg, input)
}
