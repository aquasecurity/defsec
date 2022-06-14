package builtin.kubernetes.KSV049

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV049",
	"avd_id": "AVD-KSV-0049",
	"title": "Do not allow management of configmaps",
	"short_code": "no-manage-configmaps",
	"severity": "MEDIUM",
	"description": "Some workloads leverage configmaps to store sensitive data or configuration parameters that affect runtime behavior that can be modified by an attacker or combined with another issue to potentially lead to compromise.",
	"recommended_actions": "Remove write permission verbs for resource 'configmaps'",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readVerbs := ["create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

readResource = "configmaps"

manageConfigmaps[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == readResource
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := manageConfigmaps[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resource '%s' for verbs %s", [kubernetes.kind, kubernetes.name, readResource, readVerbs]))
	res := result.new(msg, badRule)
}
