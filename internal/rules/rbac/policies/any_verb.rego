# METADATA
# title: "No wildcard verb roles"
# description: "Check whether role permits wildcard verb on specific resources"
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV045
#   avd_id: AVD-KSV-0045
#   severity: CRITICAL
#   short_code: no-wildcard-verb-role
#   recommended_action: "Create a role which does not permit wildcard verb on specific resources"
#   input:
#     selector:
#     - type: rbac
package builtin.kubernetes.KSV045

import data.lib.kubernetes
import data.lib.utils

resourceRead := ["secrets", "pods", "deployments", "daemonsets", "statefulsets", "replicationcontrollers", "replicasets", "cronjobs", "jobs", "roles", "clusterroles", "rolebindings", "clusterrolebindings", "users", "groups"]

readKinds := ["Role", "ClusterRole"]

resourceAllowAnyVerbOnspecificResource[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == resourceRead[_]
	input.rules[ru].verbs[v] == "*"
}

deny[res] {
	badRule := resourceAllowAnyVerbOnspecificResource[_]
	msg := "Role permits wildcard verb on specific resources"
	res := result.new(msg, badRule)
}
