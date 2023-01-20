# METADATA
# title: "Do not allow getting shell on pods"
# description: "Check whether role permits getting shell on pods"
# scope: package
# schemas:
# - input: schema["input"]
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

readKinds := ["Role", "ClusterRole"]

get_shell_on_pod[ruleA] {
	input.kind == readKinds[_]
	some i, j
	ruleA := input.rules[i]
	ruleB := input.rules[j]
	i < j
	ruleA.apiGroups[_] == "*"
	ruleA.resources[_] == "pods/exec"
	ruleA.verbs[_] == "create"
	ruleB.apiGroups[_] == "*"
	ruleB.resources[_] == "pods"
	ruleB.verbs[_] == "get"
}

deny[res] {
	badRule := get_shell_on_pod[_]
	msg := "Role permits getting shell on pods"
	res := result.new(msg, badRule)
}
