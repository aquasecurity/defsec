# METADATA
# title: "Manage webhookconfigurations"
# description: "Webhooks can silently intercept or actively mutate/block resources as they are being created or updated. This includes secrets and pod specs."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV114
#   avd_id: AVD-KSV-0114
#   severity: Critical
#   short_code: no-manage-webhook
#   recommended_actions: "Remove webhook configuration resouces/verbs, acceptable values for verbs ['get', 'list', 'watch']"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV114

import data.lib.kubernetes
import data.lib.utils

readVerbs := ["create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

readResource = ["mutatingwebhookconfigurations", "validatingwebhookconfigurations"]

manageWebhookConfig[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == readResource[_]
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := manageWebhookConfig[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s", [kubernetes.kind, kubernetes.name, readResource, readVerbs]))
	res := result.new(msg, badRule)
}
