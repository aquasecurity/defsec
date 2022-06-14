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

readroles := ["clusterroles", "roles"]

allowing_create_role_binding_and_associate_cluster_role[ruleA] {
	input.kind == readKinds[_]
	some i, j
	ruleA := input.rules[i]
	ruleB := input.rules[j]
	i < j
	ruleA.apiGroups[_] == "rbac.authorization.k8s.io"
	ruleA.resources[_] == "rolebindings"
	ruleA.verbs[_] == "create"
	ruleA.apiGroups[_] == "rbac.authorization.k8s.io"
	ruleB.resources[_] == ["clusterroles", "roles"][_]
	ruleB.verbs[_] == "bind"
	ruleB.resourceNames[_] == "*"
	ruleB.apiGroups[_] == "rbac.authorization.k8s.io"
}

deny[res] {
	badRule := allowing_create_role_binding_and_associate_cluster_role[_]
	msg := "Role permits creation of role binding and association with privileged role"
	res := result.new(msg, badRule)
}
