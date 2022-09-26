# METADATA
# title: "Containers must not set runAsUser to 0"
# description: "Containers should be forbidden from running with a root UID."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV105
#   avd_id: AVD-KSV-0105
#   severity: LOW
#   short_code: containers-not-run-as-root
#   recommended_action: "Set 'securityContext.runAsUser' to a non-zero integer or leave undefined."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV105

import data.lib.kubernetes
import data.lib.utils

failRootUserId[securityContext] {
	container := kubernetes.containers[_]
	securityContext := container.securityContext
	securityContext.runAsUser == 0
}

failRootUserId[securityContext] {
	pod := kubernetes.pods[_]
	securityContext := pod.spec.securityContext
	securityContext.runAsUser == 0
}

deny[res] {
	cause := failRootUserId[_]
	msg := "securityContext.runAsUser should be set to a value greater than 0"
	res := result.new(msg, cause)
}
