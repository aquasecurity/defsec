package builtin.kubernetes.KSV047

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV047",
	"avd_id": "AVD-KSV-0047",
	"title": "Do not allow privilege escalation from node proxy",
	"short_code": "no-privilege-escalation-from-node-proxy",
	"severity": "HIGH",
	"description": "Check whether role permits privilege escalation from node proxy",
	"recommended_actions": "Create a role which does not permit privilege escalation from node proxy",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readVerbs := ["get", "create"]

readKinds := ["Role", "ClusterRole"]

privilegeEscalationFromNodeProxy[input.rules[ru]] {
	input.kind == readKinds[_]
	some ru, r, v
	input.rules[ru].resources[r] == "nodes/proxy"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := privilegeEscalationFromNodeProxy[_]
	msg := "Role permits privilege escalation from node proxy"
	res := result.new(msg, badRule)
}
