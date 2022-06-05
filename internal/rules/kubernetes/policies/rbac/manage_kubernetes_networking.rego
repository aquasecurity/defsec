package builtin.kubernetes.KSV056

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV056",
	"avd_id": "AVD-KSV-0056",
	"title": "Manage Kubernetes networking resources",
	"short_code": "manage_kubernetes_networking_resources",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "The ability to control which pods get service traffic directed to them allows for interception attacks. Controlling network policy allows for bypassing lateral movement restrictions.",
	"recommended_actions": "Networking resources are only allowed for verbs 'list', 'watch', 'get'",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

readKinds := ["Role", "ClusterRole"]

readVerbs := ["create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readResources := ["services", "endpoints", "endpointslices", "networkpolicies", "ingresses"]

managekubernetesNetworking {
	some ru, r, v
	kubernetes.kind == readKinds[_]
	kubernetes.object.rules[ru].resources[r] == readResources[_]
	kubernetes.object.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	managekubernetesNetworking
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s", [kubernetes.kind, kubernetes.name, readResources, readVerbs]))
	res := result.new(msg, input)
}
