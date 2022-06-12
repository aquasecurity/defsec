package builtin.kubernetes.KSV049

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV049",
	"avd_id": "AVD-KSV-0049",
	"title": "manage configmaps",
	"short_code": "manage-configmaps",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
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

manageConfigmaps {
	some ru, r, v
	kubernetes.kind == readKinds[_]
	kubernetes.object.rules[ru].resources[r] == readResource
	kubernetes.object.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	manageConfigmaps
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resource '%s' for verbs %s", [kubernetes.kind, kubernetes.name, readResource, readVerbs]))
	res := result.new(msg, input)
}
