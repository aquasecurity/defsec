package builtin.kubernetes.KSV050

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV050",
	"avd_id": "AVD-KSV-0050",
	"title": "Manage Kubernetes RBAC resources",
	"short_code": "manage_kubernetes_RBAC_resources",
	"severity": "CRITICAL",
	"type": "Kubernetes Security Check",
	"description": "An effective level of access equivalent to cluster-admin.",
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

manageK8sRBACResources {
	some ru, r, v
	kubernetes.kind == readKinds[_]
	kubernetes.object.rules[ru].resources[r] == readResources[_]
	kubernetes.object.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	manageK8sRBACResources
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s", [kubernetes.kind, kubernetes.name, readResources, readVerbs]))
	res := result.new(msg, input)
}
