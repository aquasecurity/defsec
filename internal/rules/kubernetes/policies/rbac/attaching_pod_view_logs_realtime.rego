package builtin.kubernetes.KSV054

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV054",
	"avd_id": "AVD-KSV-0054",
	"title": "attaching shell on pods",
	"short_code": "attaching-shell-pods",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit attaching shell on pods",
	"recommended_actions": "create a Role which do not permit attaching shell on pods",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

readKinds := ["Role", "ClusterRole"]

attach_shell_on_pod {
	input.kind == readKinds[_]
	input.rules[_].apiGroups[_] == "*"
	input.rules[_].resources[_] == "pods/attach"
	input.rules[_].verbs[_] == "create"
	input.rules[_].apiGroups[_] == "*"
	input.rules[_].resources[_] == "pods"
	input.rules[_].verbs[_] == "get"
}

deny[res] {
	attach_shell_on_pod
	msg := "role permit getting shell on pods"
	res := result.new(msg, input)
}
