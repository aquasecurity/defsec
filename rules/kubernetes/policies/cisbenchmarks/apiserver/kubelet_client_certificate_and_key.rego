# METADATA
# title: "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate"
# description: "Enable certificate based kubelet authentication."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0005
#   avd_id: AVD-KCV-0005
#   severity: LOW
#   short_code: ensure-kubelet-client-certificate-and-kubelet-client-key-are-set
#   recommended_action: "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and kubelets."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0005

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--kubelet-client-certificate")
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--kubelet-client-key")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate"
	res := result.new(msg, output)
}
