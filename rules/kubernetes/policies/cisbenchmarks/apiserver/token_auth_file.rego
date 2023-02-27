# METADATA
# title: "Ensure that the --token-auth-file parameter is not set"
# description: "Do not use token based authentication."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0002
#   avd_id: AVD-KCV-0002
#   severity: LOW
#   short_code: ensure-token-auth-file-parameter-is-not-set
#   recommended_action: "Follow the documentation and configure alternate mechanisms for authentication. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --token-auth-file=<filename> parameter."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0002

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	some i
	regex.match("--token-auth-file", container.command[i])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --token-auth-file parameter is not set"
	res := result.new(msg, output)
}
