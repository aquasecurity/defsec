package builtin.kubernetes.KSV050

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV050",
	"avd_id": "AVD-KSV-0050",
	"title": "Do not allow management of RBAC resources",
	"short_code": "no-manage-rbac-resources",
	"severity": "CRITICAL",
	"description": "An effective level of access equivalent to cluster-admin should not be provided.",
	"recommended_actions": "Remove write permission verbs for resource 'roles' and 'rolebindings'",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readVerbs := ["create", "update", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

readResources := ["roles", "rolebindings"]

manageK8sRBACResources[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == readResources[_]
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := manageK8sRBACResources[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s", [kubernetes.kind, kubernetes.name, readResources, readVerbs]))
	res := result.new(msg, badRule)
}
