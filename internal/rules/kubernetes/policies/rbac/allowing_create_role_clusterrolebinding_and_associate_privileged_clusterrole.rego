package builtin.kubernetes.KSV052

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV052",
	"avd_id": "AVD-KSV-0052",
	"title": "allow role clusterrolebindings and associate to privileged cluster role",
	"short_code": "allow-role-clusterrolebindings-associate-privileged-cluster-role",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit creating role clusterrolebindings and associate to privileged cluster role",
	"recommended_actions": "create a Role which do not ermit to create role clusterrolebindings and associate to privileged cluster role",
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
	msg := "role permit create role binding and associate to role"
	res := result.new(msg, input)
}
