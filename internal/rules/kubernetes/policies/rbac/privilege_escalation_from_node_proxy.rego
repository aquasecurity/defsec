package builtin.kubernetes.KSV047

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV047",
	"avd_id": "AVD-KSV-0047",
	"title": "privilege escalation from node proxy",
	"short_code": "privilege-escalation-from-node-proxy",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit privilege escalation from node proxy",
	"recommended_actions": "create a Role which do not permit privilege escalation from node proxy",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readVerbs := ["get", "create"]

readKinds := ["Role", "ClusterRole"]

privilegeEscalationFromNodeProxy {
	input.kind == readKinds[_]
	some ru, r, v
	input.rules[ru].resources[r] == "nodes/proxy"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	privilegeEscalationFromNodeProxy
	msg := "role permit privilege escalation from node proxy"
	res := result.new(msg, input)
}
