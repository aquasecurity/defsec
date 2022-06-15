package builtin.kubernetes.KSV056

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV056",
	"avd_id": "AVD-KSV-0056",
	"title": "Do not allow management of networking resources",
	"short_code": "no-manage-networking-resources",
	"severity": "HIGH",
	"description": "The ability to control which pods get service traffic directed to them allows for interception attacks. Controlling network policy allows for bypassing lateral movement restrictions.",
	"recommended_actions": "Networking resources are only allowed for verbs 'list', 'watch', 'get'",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readKinds := ["Role", "ClusterRole"]

readVerbs := ["create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readResources := ["services", "endpoints", "endpointslices", "networkpolicies", "ingresses"]

managekubernetesNetworking[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == readResources[_]
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := managekubernetesNetworking[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s", [kubernetes.kind, kubernetes.name, readResources, readVerbs]))
	res := result.new(msg, badRule)
}
