# METADATA
# title: "Manage Kubernetes RBAC resources"
# description: "An effective level of access equivalent to cluster-admin should not be provided."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV050
#   avd_id: AVD-KSV-0050
#   severity: CRITICAL
#   short_code: no-manage-rbac-resources
#   recommended_action: "Remove write permission verbs for resource 'roles' and 'rolebindings'"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: clusterrole
#         - kind: role
package builtin.kubernetes.KSV050

import data.lib.kubernetes
import data.lib.utils

readVerbs := ["create", "update", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

readResources := ["roles", "rolebindings"]

manageK8sRBACResources[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == readResources[_]
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := manageK8sRBACResources[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s", [kubernetes.kind, kubernetes.name, readResources, readVerbs]))
	res := result.new(msg, badRule)
}
