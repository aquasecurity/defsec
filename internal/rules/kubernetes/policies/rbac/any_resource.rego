package builtin.kubernetes.KSV046

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV046",
	"avd_id": "AVD-KSV-0046",
	"title": "any resource role",
	"short_code": "any-resource-role",
	"severity": "CRITICAL",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit specific verb on any resources",
	"recommended_actions": "create a Role which do not permit specific verb on any resources",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

readVerbs := ["create", "update", "delete", "deletecollection", "impersonate", "*", "list", "get"]

readKinds := ["Role", "ClusterRole"]

resourceAllowSpecificVerbOnAnyResource {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "*"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	resourceAllowSpecificVerbOnAnyResource
	msg := "role permit specific verb on any resources"
	res := result.new(msg, input)
}
