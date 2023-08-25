# METADATA
# title: "Manage secrets"
# description: "Viewing secrets at the cluster-scope is akin to cluster-admin in most clusters as there are typically at least one service accounts (their token stored in a secret) bound to cluster-admin directly or a role/clusterrole that gives similar permissions."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV041
#   avd_id: AVD-KSV-0041
#   severity: CRITICAL
#   short_code: no-manage-secrets
#   recommended_actions: "Manage secrets are not allowed. Remove resource 'secrets' from cluster role"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: clusterrole
package builtin.kubernetes.KSV041

import data.lib.kubernetes
import data.lib.utils

readVerbs := ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["ClusterRole"]

resourceManageSecret[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "secrets"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := resourceManageSecret[_]
	msg := kubernetes.format(sprintf("%s '%s' shouldn't have access to manage resource 'secrets'", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, badRule)
}
