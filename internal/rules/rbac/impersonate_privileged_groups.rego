package builtin.kubernetes.KSV043

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV043",
	"avd_id": "AVD-KSV-0043",
	"title": "Do not allow impersonation of privileged groups",
	"short_code": "no-impersonate-privileged-groups",
	"severity": "CRITICAL",
	"description": "Check whether role permits impersonating privileged groups",
	"recommended_actions": "Create a role which does not permit to impersonate privileged groups if not needed",
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
	msg := "Role permits impersonation of privileged groups"
	res := result.new(msg, input)
}
