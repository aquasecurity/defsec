package builtin.kubernetes.KSV045

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV045",
	"avd_id": "AVD-KSV-0045",
	"title": "No wildcard verb roles",
	"short_code": "no-wildcard-verb-role",
	"severity": "CRITICAL",
	"description": "Check whether role permits wildcard verb on specific resources",
	"recommended_actions": "Create a role which does not permit wildcard verb on specific resources",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

resourceRead := ["secrets", "pods", "deployments", "daemonsets", "statefulsets", "replicationcontrollers", "replicasets", "cronjobs", "jobs", "roles", "clusterroles", "rolebindings", "clusterrolebindings", "users", "groups"]

readKinds := ["Role", "ClusterRole"]

resourceAllowAnyVerbOnspecificResource[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == resourceRead[_]
	input.rules[ru].verbs[v] == "*"
}

deny[res] {
	badRule := resourceAllowAnyVerbOnspecificResource[_]
	msg := "Role permits wildcard verb on specific resources"
	res := result.new(msg, badRule)
}
