# METADATA
# title: "Ensure that the --bind-address argument is set to 127.0.0.1"
# description: "Do not bind the scheduler service to non-loopback insecure addresses."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KCV0039
#   avd_id: AVD-KCV-0039
#   severity: LOW
#   recommended_action: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and ensure the correct value for the --bind-address parameter"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0039

import data.lib.kubernetes
import data.lib.result

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_controllermananager(container)
	not kubernetes.command_has_flag(container.command, "--bind-address=127.0.0.1")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --bind-address argument is set to 127.0.0.1"
	res := result.new(msg, output)
}
