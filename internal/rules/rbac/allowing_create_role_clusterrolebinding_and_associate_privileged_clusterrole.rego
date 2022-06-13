package builtin.kubernetes.KSV052

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV052",
	"avd_id": "AVD-KSV-0052",
	"title": "Do not allow role to create ClusterRoleBindings and association with privileged role",
	"short_code": "allow-role-clusterrolebindings-associate-privileged-cluster-role",
	"severity": "HIGH",
	"description": "Check whether role permits creating role ClusterRoleBindings and association with privileged cluster role",
	"recommended_actions": "Create a role which does not permit to create role clusterrolebindings and associate to privileged cluster role",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readKinds := ["Role", "ClusterRole"]

allowing_create_clusterrolebindings_binding_and_associate_cluster_role {
	input.kind == readKinds[_]
	input.rules[_].apiGroups[_] == "rbac.authorization.k8s.io"
	input.rules[_].resources[_] == "clusterrolebindings"
	input.rules[_].verbs[_] == "create"
	input.rules[_].apiGroups[_] == "rbac.authorization.k8s.io"
	input.rules[_].resources[_] == "clusterroles"
	input.rules[_].verbs[_] == "bind"
	input.rules[_].resourceNames[_] == "*"
}

deny[res] {
	allowing_create_clusterrolebindings_binding_and_associate_cluster_role
	msg := "Role permits creation of role binding and association with privileged role"
	res := result.new(msg, input)
}
