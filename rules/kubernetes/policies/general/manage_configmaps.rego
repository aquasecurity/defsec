# METADATA
# title: "Manage configmaps"
# description: "Some workloads leverage configmaps to store sensitive data or configuration parameters that affect runtime behavior that can be modified by an attacker or combined with another issue to potentially lead to compromise."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV049
#   avd_id: AVD-KSV-0049
#   severity: MEDIUM
#   short_code: no-manage-configmaps
#   recommended_action: "Remove write permission verbs for resource 'configmaps'"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV049

import data.lib.kubernetes
import data.lib.utils

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
