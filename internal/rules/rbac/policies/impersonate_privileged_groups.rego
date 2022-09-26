# METADATA
# title: "Do not allow impersonation of privileged groups"
# description: "Check whether role permits impersonating privileged groups"
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV043
#   avd_id: AVD-KSV-0043
#   severity: CRITICAL
#   short_code: no-impersonate-privileged-groups
#   recommended_action: "Create a role which does not permit to impersonate privileged groups if not needed"
#   input:
#     selector:
#     - type: rbac
package builtin.kubernetes.KSV043

import data.lib.kubernetes
import data.lib.utils

readKinds := ["Role", "ClusterRole"]

impersonatePrivilegedGroups[input.rules[ru]] {
	some ru
	input.kind == readKinds[_]
	input.rules[ru].apiGroups[_] == "*"
	input.rules[ru].resources[_] == "groups"
	input.rules[ru].verbs[_] == "impersonate"
}

deny[res] {
	badRule := impersonatePrivilegedGroups[_]
	msg := "Role permits impersonation of privileged groups"
	res := result.new(msg, badRule)
}
