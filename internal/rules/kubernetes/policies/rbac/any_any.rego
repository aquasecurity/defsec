package builtin.kubernetes.KSV044

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV044",
	"avd_id": "AVD-KSV-0044",
	"title": "any any role",
	"short_code": "any-any-role",
	"severity": "CRITICAL",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit any verb on any resource",
	"recommended_actions": "create a Role which do not permit any verb on any resource",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readKinds := ["Role", "ClusterRole"]

anyAnyResource {
	input.kind == readKinds[_]
	input.rules[_].apiGroups[_] == "*"
	input.rules[_].resources[_] == "*"
	input.rules[_].verbs[_] == "*"
}

deny[res] {
	anyAnyResource
	msg := "role permit any verb on any resource"
	res := result.new(msg, input)
}
