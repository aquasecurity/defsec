# METADATA
# title: "Seccomp profile unconfined"
# description: "Seccomp profile must not be explicitly set to 'Unconfined'."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV104
#   avd_id: AVD-KSV-0104
#   severity: MEDIUM
#   short_code: no-seccomp-unconfined
#   recommended_action: "Do not set seccomp profile to 'Unconfined'"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV104

import data.lib.kubernetes
import data.lib.utils

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
