# METADATA
# title: "Access to host network"
# description: "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV009
#   avd_id: AVD-KSV-0009
#   severity: HIGH
#   short_code: no-host-network
#   recommended_action: "Do not set 'spec.template.spec.hostNetwork' to true."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV009

import data.lib.kubernetes

default failHostNetwork = false

# failHostNetwork is true if spec.hostNetwork is set to true (on all controllers)
failHostNetwork {
	kubernetes.host_networks[_] == true
}

deny[res] {
	failHostNetwork
	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.spec.hostNetwork' to true", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
