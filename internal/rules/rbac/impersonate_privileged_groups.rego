package builtin.kubernetes.KSV043

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV043",
	"avd_id": "AVD-KSV-0043",
	"title": "impersonate privileged groups",
	"short_code": "impersonate-privileged-groups",
	"severity": "CRITICAL",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit impersonating privileged groups",
	"recommended_actions": "create a Role which do not permit to impersonate privileged groups if not needed",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readKinds := ["Role", "ClusterRole"]

impersonatePrivilegedGroups {
	input.kind == readKinds[_]
	input.rules[_].apiGroups[_] == "*"
	input.rules[_].resources[_] == "groups"
	input.rules[_].verbs[_] == "impersonate"
}

deny[res] {
	impersonatePrivilegedGroups
	msg := "role permit to impersonate privileged groups"
	res := result.new(msg, input)
}
