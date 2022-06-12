package builtin.kubernetes.KSV053

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV053",
	"avd_id": "AVD-KSV-0053",
	"title": "getting shell on pods",
	"short_code": "getting-shell-pods",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit getting shell on pods",
	"recommended_actions": "create a Role which do not permit getting shell on pods",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readKinds := ["Role", "ClusterRole"]

get_shell_on_pod {
	input.kind == readKinds[_]
	input.rules[_].apiGroups[_] == "*"
	input.rules[_].resources[_] == "pods/exec"
	input.rules[_].verbs[_] == "create"
	input.rules[_].apiGroups[_] == "*"
	input.rules[_].resources[_] == "pods"
	input.rules[_].verbs[_] == "get"
}

deny[res] {
	get_shell_on_pod
	msg := "role permit getting shell on pods"
	res := result.new(msg, input)
}
