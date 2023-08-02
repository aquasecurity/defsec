# METADATA
# title: "Manage all resources at the namespace"
# description: "Full control of the resources within a namespace.  In some cluster configurations, this is excessive. In others, this is normal (a gitops deployment operator like flux)"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV112
#   avd_id: AVD-KSV-0112
#   severity: CRITICAL
#   short_code: no-wildcard-resource-role
#   recommended_actions: "Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by role in namespace"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV112

import data.lib.kubernetes
import data.lib.utils

readVerbs := ["create", "update", "delete", "deletecollection", "impersonate", "*", "list", "get"]

readKinds := ["Role"]

managingAllResourcesAtNamespace[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "*"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := managingAllResourcesAtNamespace[_]
	msg := kubernetes.format(sprintf("%s '%s' shouldn't manage all resources at the namespace '%s'", [kubernetes.kind, kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, badRule)
}
