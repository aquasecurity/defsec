# METADATA
# title: "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate"
# description: "Activate garbage collector on pod termination, as appropriate."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KCV0033
#   avd_id: AVD-KCV-0033
#   severity: LOW
#   short_code: ensure-terminated-pod-gc-threshold-argument-is-set-as-appropriate
#   recommended_action: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --terminated-pod-gc-threshold to an appropriate threshold."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0033

import data.lib.kubernetes
import data.lib.result

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_controllermananager(container)
	not kubernetes.command_has_flag(container.command, "--terminated-pod-gc-threshold")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate"
	res := result.new(msg, output)
}
