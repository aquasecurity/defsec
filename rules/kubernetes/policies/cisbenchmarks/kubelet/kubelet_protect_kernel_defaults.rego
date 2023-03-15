# METADATA
# title: "Ensure that the --protect-kernel-defaults is set to true"
# description: "Protect tuned kernel parameters from overriding kubelet default kernel parameter values."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0083
#   avd_id: AVD-KCV-0083
#   severity: HIGH
#   short_code: ensure-protect-kernel-defaults-set-true
#   recommended_action: "If using a Kubelet config file, edit the file to set protectKernelDefaults: true"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0083

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_anonymous_auth_set(sp) := {"kubeletProtectKernelDefaultsArgumentSet": violation} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {kernel_defaults | kernel_defaults = sp.info.kubeletProtectKernelDefaultsArgumentSet.values[_]; not kernel_defaults == "true"}
	count(violation) > 0
}

validate_kubelet_anonymous_auth_set(sp) := {"kubeletProtectKernelDefaultsArgumentSet": kernel_defaults} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletProtectKernelDefaultsArgumentSet.values) == 0
	kernel_defaults = {}
}

deny[res] {
	output := validate_kubelet_anonymous_auth_set(input)
	msg := "Ensure that the --protect-kernel-defaults is set to true"
	res := result.new(msg, output)
}
