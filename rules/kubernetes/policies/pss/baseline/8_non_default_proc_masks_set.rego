# METADATA
# title: "Non-default /proc masks set"
# description: "The default /proc masks are set up to reduce attack surface, and should be required."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV027
#   avd_id: AVD-KSV-0027
#   severity: MEDIUM
#   short_code: no-custom-proc-mask
#   recommended_action: "Do not set spec.containers[*].securityContext.procMount and spec.initContainers[*].securityContext.procMount."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV027

import data.lib.kubernetes
import data.lib.utils

default failProcMount = false

# failProcMountOpts is true if securityContext.procMount is set in any container
failProcMountOpts[container] {
	container := kubernetes.containers[_]
	utils.has_key(container.securityContext, "procMount")
}

deny[res] {
	output := failProcMountOpts[_]
	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.containers[*].securityContext.procMount' or 'spec.initContainers[*].securityContext.procMount'", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
