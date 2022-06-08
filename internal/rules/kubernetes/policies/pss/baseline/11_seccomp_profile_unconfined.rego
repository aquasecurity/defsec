package builtin.kubernetes.KSV104

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV104",
	"avd_id": "AVD-KSV-0104",
	"title": "Seccomp profile unconfined",
	"short_code": "no-seccomp-unconfined",
	"severity": "MEDIUM",
	"description": "Seccomp profile must not be explicitly set to 'Unconfined'.",
	"recommended_actions": "Do not set seccomp profile to 'Unconfined'",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

failSeccomp[profile] {
	spec := input.spec
	profile := spec.securityContext.seccompProfile
	profile.type == "Unconfined"
}

failSeccomp[profile] {
	container := kubernetes.containers[_]
	profile := container.securityContext.seccompProfile
	profile.type == "Unconfined"
}

deny[res] {
	cause := failSeccomp[_]
	msg := "You should not set Seccomp profile to 'Unconfined'."
	res := result.new(msg, cause)
}
