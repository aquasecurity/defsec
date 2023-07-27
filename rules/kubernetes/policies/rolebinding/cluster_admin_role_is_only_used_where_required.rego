# METADATA
# title: "User with admin access"
# description: "The RBAC role cluster-admin provides wide-ranging powers over the environment and should be used only where and when needed."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV111
#   avd_id: AVD-KSV-0111
#   severity: MEDIUM
#   short_code: cluster-admin0-role-only-used-where-required"
#   recommended_action: "Identify all clusterrolebindings to the cluster-admin role. Check if they are used and if they need this role or if they could use a role with fewer privileges."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV111

import data.lib.kubernetes

readRoleRefs := ["cluster-admin", "admin", "edit"]

roleBindings := ["clusterrolebinding", "rolebinding"]

clusterAdminRoleInUse(roleBinding) {
	lower(kubernetes.kind) == roleBindings[_]
	roleBinding.roleRef.name == readRoleRefs[_]
}

deny[res] {
	clusterAdminRoleInUse(input)
	msg := kubernetes.format(sprintf("%s '%s' should not bind to roles %s", [kubernetes.kind, kubernetes.name, readRoleRefs]))
	res := result.new(msg, input.metadata)
}
