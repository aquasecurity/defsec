# METADATA
# title: "Ensure that the --service-account-key-file argument is set as appropriate"
# description: "Explicitly set a service account public key file for service accounts on the apiserver."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0025
#   avd_id: AVD-KCV-0025
#   severity: LOW
#   short_code: ensure-service-account-key-file-argument-is-set-as-appropriate
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --service-account-key-file parameter to the public key file for service accounts."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0025

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--service-account-key-file")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --service-account-key-file argument is set as appropriate"
	res := result.new(msg, output)
}
