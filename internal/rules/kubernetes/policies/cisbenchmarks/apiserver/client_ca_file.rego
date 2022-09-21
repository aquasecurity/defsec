# METADATA
# title: "Ensure that the --client-ca-file argument is set as appropriate"
# description: "Setup TLS connection on the API server."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KCV0028
#   avd_id: AVD-KCV-0028
#   severity: LOW
#   short_code: ensure-client-ca-file-argument-is-set-as-appropriate
#   recommended_action: "Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the client certificate authority file."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0028

import data.lib.kubernetes
import data.lib.result

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	kubernetes.command_has_flag(container.command, "--client-ca-file")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --client-ca-file argument is set as appropriate"
	res := result.new(msg, output)
}
