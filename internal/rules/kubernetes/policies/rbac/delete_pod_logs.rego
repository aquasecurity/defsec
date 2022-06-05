package builtin.kubernetes.KSV042

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV042",
	"avd_id": "AVD-KSV-0042",
	"title": "Delete pod logs",
	"short_code": "delete-pod-logs",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Used to cover attacker’s tracks, but most clusters ship logs quickly off-cluster.",
	"recommended_actions": "Remove verbs 'delete' and 'deletecollection' for resource 'pods/log' for Role and ClusterRole",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

readVerbs := ["delete", "deletecollection", "*"]

readKinds := ["Role", "ClusterRole"]

deletePodsLogRestricted {
	some ru, r, v
	kubernetes.kind == readKinds[_]
	kubernetes.object.rules[ru].resources[r] == "pods/log"
	kubernetes.object.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	deletePodsLogRestricted
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resource 'pods/log' for verbs %s", [kubernetes.kind, kubernetes.name, readVerbs]))
	res := result.new(msg, input)
}
