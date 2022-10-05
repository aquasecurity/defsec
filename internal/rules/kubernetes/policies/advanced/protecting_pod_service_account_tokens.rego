# METADATA
# title: "Protecting Pod service account tokens"
# description: "ensure that Pod specifications disable the secret token being mounted by setting automountServiceAccountToken: false"
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#serviceaccount-admission-controller
# custom:
#   id: KSV036
#   avd_id: AVD-KSV-0036
#   severity: MEDIUM
#   short_code: no-auto-mount-service-token
#   recommended_action: "Disable the mounting of service account secret token by setting automountServiceAccountToken to false"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV036

import data.lib.kubernetes
import data.lib.utils

mountServiceAccountToken(spec) {
	utils.has_key(spec, "automountServiceAccountToken")
	spec.automountServiceAccountToken == true
}

# if there is no automountServiceAccountToken spec, check on volumeMount in containers. Service Account token is mounted on /var/run/secrets/kubernetes.io/serviceaccount
mountServiceAccountToken(spec) {
	not utils.has_key(spec, "automountServiceAccountToken")
	"/var/run/secrets/kubernetes.io/serviceaccount" == kubernetes.containers[_].volumeMounts[_].mountPath
}

deny[res] {
	mountServiceAccountToken(input.spec)
	msg := kubernetes.format(sprintf("Container of %s '%s' should set 'spec.automountServiceAccountToken' to false", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
