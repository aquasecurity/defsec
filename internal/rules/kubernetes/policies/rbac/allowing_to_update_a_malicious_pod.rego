package builtin.kubernetes.KSV048

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV048",
	"avd_id": "AVD-KSV-0048",
	"title": "allowing to update/create a malicious pod",
	"short_code": "allowing-update-malicious-pod",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit update/create a malicious pod",
	"recommended_actions": "create a Role which do not permit update/create a malicious pod",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

workloads := ["deployments", "daemonsets", "statefulsets", "replicationcontrollers", "replicasets", "jobs", "cronjobs"]

changeVerbs := ["update", "create", "*"]

readKinds := ["Role", "ClusterRole"]

update_malicious_pod {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == workloads[_]
	input.rules[ru].verbs[v] == changeVerbs[_]
}

deny[res] {
	update_malicious_pod
	msg := "role permit to update malicious pod"
	res := result.new(msg, input)
}
