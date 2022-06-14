package builtin.kubernetes.KSV048

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV048",
	"avd_id": "AVD-KSV-0048",
	"title": "Do not allow update/create of a malicious pod",
	"short_code": "deny-create-update-malicious-pod",
	"severity": "HIGH",
	"description": "Check whether role permits update/create of a malicious pod",
	"recommended_actions": "Create a role which does not permit update/create of a malicious pod",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

workloads := ["deployments", "daemonsets", "statefulsets", "replicationcontrollers", "replicasets", "jobs", "cronjobs"]

changeVerbs := ["update", "create", "*"]

readKinds := ["Role", "ClusterRole"]

update_malicious_pod[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == workloads[_]
	input.rules[ru].verbs[v] == changeVerbs[_]
}

deny[res] {
	badRule := update_malicious_pod[_]
	msg := "Role permits create/update of a malicious pod"
	res := result.new(msg, badRule)
}
