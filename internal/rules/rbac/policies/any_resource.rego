# METADATA
# title: "No wildcard resource roles"
# description: "Check whether role permits specific verb on wildcard resources"
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV046
#   avd_id: AVD-KSV-0046
#   severity: CRITICAL
#   short_code: no-wildcard-resource-role
#   recommended_action: "Create a role which does not permit specific verb on wildcard resources"
#   input:
#     selector:
#     - type: rbac
package builtin.kubernetes.KSV046

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

readVerbs := ["create", "update", "delete", "deletecollection", "impersonate", "*", "list", "get"]

readKinds := ["Role", "ClusterRole"]

resourceAllowSpecificVerbOnAnyResource[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "*"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := resourceAllowSpecificVerbOnAnyResource[_]
	msg := "Role permits specific verb on wildcard resource"
	res := result.new(msg, badRule)
}
