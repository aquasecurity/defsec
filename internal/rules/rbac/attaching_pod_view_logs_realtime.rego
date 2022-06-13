package builtin.kubernetes.KSV054

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV054",
	"avd_id": "AVD-KSV-0054",
	"title": "Do not allow attaching to shell on pods",
	"short_code": "no-attaching-shell-pods",
	"severity": "HIGH",
	"description": "Check whether role permits attaching to shell on pods",
	"recommended_actions": "Create a role which does not permit attaching to shell on pods",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
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
	msg := "Role permits attaching to shell on pods"
	res := result.new(msg, input)
}
