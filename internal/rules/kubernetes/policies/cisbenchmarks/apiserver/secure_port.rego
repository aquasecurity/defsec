# METADATA
# title: "Ensure that the --secure-port argument is not set to 0"
# description: "Do not disable the secure port."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KCV0017
#   avd_id: AVD-KCV-0017
#   severity: LOW
#   short_code: ensure-secure-port-argument-is-not-set-to-0
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and either remove the --secure-port parameter or set it to a different (non-zero) desired port."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0017

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	kubernetes.command_has_flag(container.command, "--secure-port=0")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --secure-port argument is not set to 0"
	res := result.new(msg, output)
}
