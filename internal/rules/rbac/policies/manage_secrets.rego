# METADATA
# title: "Do not allow management of secrets"
# description: "Check whether role permits managing secrets"
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV041
#   avd_id: AVD-KSV-0041
#   severity: CRITICAL
#   short_code: no-manage-secrets
#   recommended_action: "Create a role which does not permit to manage secrets if not needed"
#   input:
#     selector:
#     - type: rbac
package builtin.kubernetes.KSV041

import data.lib.kubernetes
import data.lib.utils

readVerbs := ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

resourceManageSecret[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "secrets"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := resourceManageSecret[_]
	msg := "Role permits management of secret(s)"
	res := result.new(msg, badRule)
}
