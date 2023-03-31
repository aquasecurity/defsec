# METADATA
# title: "Do not allow role to create ClusterRoleBindings and association with privileged role"
# description: "Check whether role permits creating role ClusterRoleBindings and association with privileged cluster role"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV052
#   avd_id: AVD-KSV-0052
#   severity: HIGH
#   short_code: allow-role-clusterrolebindings-associate-privileged-cluster-role
#   recommended_action: "Create a role which does not permit to create role clusterrolebindings and associate to privileged cluster role"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV052

import data.lib.kubernetes
import data.lib.utils

readKinds := ["Role", "ClusterRole"]

allowing_create_clusterrolebindings_binding_and_associate_cluster_role[ruleA] {
	input.kind == readKinds[_]
	some i, j
	ruleA := input.rules[i]
	ruleB := input.rules[j]
	i < j
	ruleA.apiGroups[_] == "rbac.authorization.k8s.io"
	ruleA.resources[_] == "clusterrolebindings"
	ruleA.verbs[_] == "create"
	ruleA.apiGroups[_] == "rbac.authorization.k8s.io"
	ruleB.resources[_] == "clusterroles"
	ruleB.verbs[_] == "bind"
	ruleB.resourceNames[_] == "*"
}

deny[res] {
	badRule := allowing_create_clusterrolebindings_binding_and_associate_cluster_role[_]
	msg := "Role permits creation of role binding and association with privileged role"
	res := result.new(msg, badRule)
}
