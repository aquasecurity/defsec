package builtin.kubernetes.KSV045

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV045",
	"avd_id": "AVD-KSV-0045",
	"title": "any verb role",
	"short_code": "any-verb-role",
	"severity": "CRITICAL",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit any verb on specific resources",
	"recommended_actions": "create a Role which do not permit any verb on specific resources",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

resourceRead := ["secrets", "pods", "deployments", "daemonsets", "statefulsets", "replicationcontrollers", "replicasets", "cronjobs", "jobs", "roles", "clusterroles", "rolebindings", "clusterrolebindings", "users", "groups"]

readKinds := ["Role", "ClusterRole"]

resourceAllowAnyVerbOnspecificResource {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == resourceRead[_]
	input.rules[ru].verbs[v] == "*"
}

deny[res] {
	resourceAllowAnyVerbOnspecificResource
	msg := "role permit any verb on specific resources"
	res := result.new(msg, input)
}
