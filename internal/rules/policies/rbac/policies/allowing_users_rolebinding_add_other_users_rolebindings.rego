# METADATA
# title: "Do not allow users in a rolebinding to add other users to their rolebindings"
# description: "Check whether role permits allowing users in a rolebinding to add other users to their rolebindings"
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV055
#   avd_id: AVD-KSV-0055
#   severity: LOW
#   short_code: view-all-secrets
#   recommended_action: "Create a role which does not permit allowing users in a rolebinding to add other users to their rolebindings if not needed"
#   input:
#     selector:
#     - type: rbac
package builtin.kubernetes.KSV055

import data.lib.kubernetes
import data.lib.utils

readKinds := ["Role", "ClusterRole"]

allowing_users_rolebinding_add_other_users_their_rolebindings[input.rules[ru]] {
	some ru
	input.kind == readKinds[_]
	input.rules[ru].apiGroups[_] == "*"
	input.rules[ru].resources[_] == "rolebindings"
	input.rules[ru].verbs[_] == "get"
	input.rules[ru].verbs[_] == "patch"
}

deny[res] {
	badRule := allowing_users_rolebinding_add_other_users_their_rolebindings[_]
	msg := "Role permits allowing users in a rolebinding to add other users to their rolebindings"
	res := result.new(msg, badRule)
}
