# METADATA
# title: "Ensure that the --use-service-account-credentials argument is set to true"
# description: "Use individual service account credentials for each controller."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0135
#   avd_id: AVD-KCV-0035
#   severity: LOW
#   short_code: ensure-use-service-account-credentials-argument-is-set-to-true
#   recommended_action: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node to set the below parameter."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0035

import data.lib.kubernetes

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_controllermananager(container)
	not kubernetes.command_has_flag(container.command, "--use-service-account-credentials=true")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --use-service-account-credentials argument is set to true"
	res := result.new(msg, output)
}
