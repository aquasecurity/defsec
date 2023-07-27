# METADATA
# title: "Delete pod logs"
# description: "Used to cover attacker’s tracks, but most clusters ship logs quickly off-cluster."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV042
#   avd_id: AVD-KSV-0042
#   severity: MEDIUM
#   short_code: no-delete-pod-logs
#   recommended_action: "Remove verbs 'delete' and 'deletecollection' for resource 'pods/log' for Role and ClusterRole"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV042

import data.lib.kubernetes
import data.lib.utils

readVerbs := ["delete", "deletecollection", "*"]

readKinds := ["Role", "ClusterRole"]

deletePodsLogRestricted[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "pods/log"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := deletePodsLogRestricted[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resource 'pods/log' for verbs %s", [kubernetes.kind, kubernetes.name, readVerbs]))
	res := result.new(msg, badRule)
}
