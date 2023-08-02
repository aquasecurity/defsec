# METADATA
# title: "Ensure that the --root-ca-file argument is set as appropriate"
# description: "Allow pods to verify the API server's serving certificate before establishing connections."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0037
#   avd_id: AVD-KCV-0037
#   severity: LOW
#   short_code: ensure-root-ca-file-argument-is-set-as-appropriate
#   recommended_action: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --root-ca-file parameter to the certificate bundle file`."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0037

import data.lib.kubernetes

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_controllermanager(container)
	not kubernetes.command_has_flag(container.command, "--root-ca-file")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --root-ca-file argument is set as appropriate"
	res := result.new(msg, output)
}
