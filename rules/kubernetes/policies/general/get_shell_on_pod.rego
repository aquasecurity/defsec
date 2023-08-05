# METADATA
# title: "Exec into Pods"
# description: "Check whether role permits getting shell on pods"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV053
#   avd_id: AVD-KSV-0053
#   severity: HIGH
#   short_code: no-getting-shell-pods
#   recommended_action: "Create a role which does not permit getting shell on pods"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV053

import data.lib.kubernetes
import data.lib.utils

workloads := ["pods/exec"]

changeVerbs := ["create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

execPodsRestricted[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == workloads[_]
	input.rules[ru].verbs[v] == changeVerbs[_]
}

deny[res] {
	badRule := execPodsRestricted[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resource '%s' for verbs %s", [kubernetes.kind, kubernetes.name, workloads, changeVerbs]))
	res := result.new(msg, badRule)
}
