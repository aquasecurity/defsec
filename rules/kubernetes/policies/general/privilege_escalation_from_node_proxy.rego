# METADATA
# title: "Do not allow privilege escalation from node proxy"
# description: "Check whether role permits privilege escalation from node proxy"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV047
#   avd_id: AVD-KSV-0047
#   severity: HIGH
#   short_code: no-privilege-escalation-from-node-proxy
#   recommended_action: "Create a role which does not permit privilege escalation from node proxy"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV047

import data.lib.kubernetes
import data.lib.utils

readVerbs := ["get", "create"]

readKinds := ["Role", "ClusterRole"]

privilegeEscalationFromNodeProxy[input.rules[ru]] {
	input.kind == readKinds[_]
	some ru, r, v
	input.rules[ru].resources[r] == "nodes/proxy"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := privilegeEscalationFromNodeProxy[_]
	msg := "Role permits privilege escalation from node proxy"
	res := result.new(msg, badRule)
}
