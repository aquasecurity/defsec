# METADATA
# title: "HostProcess container defined"
# description: "Windows pods offer the ability to run HostProcess containers which enable privileged access to the Windows node."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV103
#   avd_id: AVD-KSV-0103
#   severity: MEDIUM
#   short_code: no-hostprocess-containers
#   recommended_action: "Do not enable 'hostProcess' on any securityContext"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV103

import data.lib.kubernetes
import data.lib.utils

failHostProcess[spec] {
	spec := input.spec
	spec.securityContext.windowsOptions.hostProcess == true
}

failHostProcess[options] {
	container := kubernetes.containers[_]
	options := container.securityContext.windowsOptions
	options.hostProcess == true
}

deny[res] {
	cause := failHostProcess[_]
	msg := "You should not enable hostProcess."
	res := result.new(msg, cause)
}
