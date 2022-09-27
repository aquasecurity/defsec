# METADATA
# title: "Ensure that the RotateKubeletServerCertificate argument is set to true"
# description: "Enable kubelet server certificate rotation on controller-manager."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KCV0038
#   avd_id: AVD-KCV-0038
#   severity: LOW
#   short_code: Ensure that the RotateKubeletServerCertificate argument is set to true
#   recommended_action: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --feature-gates parameter to include RotateKubeletServerCertificate=true ."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0038

import data.lib.kubernetes

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_controllermananager(container)
	not kubernetes.command_has_flag(container.command, "RotateKubeletServerCertificate=true")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the RotateKubeletServerCertificate argument is set to true"
	res := result.new(msg, output)
}
