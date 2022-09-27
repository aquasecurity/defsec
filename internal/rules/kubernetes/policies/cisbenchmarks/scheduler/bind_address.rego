# METADATA
# title: "Ensure that the --bind-address argument is set to 127.0.0.1"
# description: "Do not bind the scheduler service to non-loopback insecure addresses."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KCV0041
#   avd_id: AVD-KCV-0041
#   severity: LOW
#   short_code: ensure-scheduler-bind-address-is-loopback
#   recommended_action: "Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml on the Control Plane node and ensure the correct value for the --bind-address parameter."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0041

import data.lib.kubernetes

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_scheduler(container)
	not kubernetes.command_has_flag(container.command, "--bind-address=127.0.0.1")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --bind-address argument is set to 127.0.0.1"
	res := result.new(msg, output)
}
