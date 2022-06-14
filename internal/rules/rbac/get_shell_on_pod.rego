package builtin.kubernetes.KSV053

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV053",
	"avd_id": "AVD-KSV-0053",
	"title": "Do not allow getting shell on pods",
	"short_code": "no-getting-shell-pods",
	"severity": "HIGH",
	"description": "Check whether role permits getting shell on pods",
	"recommended_actions": "Create a role which does not permit getting shell on pods",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

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
