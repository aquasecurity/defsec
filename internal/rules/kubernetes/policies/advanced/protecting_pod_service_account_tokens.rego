package builtin.kubernetes.KSV036

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV036",
	"avd_id": "AVD-KSV-0036",
	"title": "Protecting Pod service account tokens",
	"short_code": "no-auto-mount-service-token",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "ensure that Pod specifications disable the secret token being mounted by setting automountServiceAccountToken: false",
	"recommended_actions": "Disable the mounting of service account secret token by setting automountServiceAccountToken to false",
	"url": "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#serviceaccount-admission-controller",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

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
