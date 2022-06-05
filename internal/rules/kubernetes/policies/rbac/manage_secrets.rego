package builtin.kubernetes.KSV041

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV041",
	"avd_id": "AVD-KSV-0041",
	"title": "manage secrets",
	"short_code": "manage-secrets",
	"severity": "CRITICAL",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit managing secrets",
	"recommended_actions": "create a Role which do not permit to manage secrets if not needed",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

readVerbs := ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

resourceManageSecret {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "secrets"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	resourceManageSecret
	msg := "role permit to view specific secret"
	res := result.new(msg, input)
}
