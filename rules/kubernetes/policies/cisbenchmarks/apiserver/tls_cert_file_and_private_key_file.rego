# METADATA
# title: "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate"
# description: "Setup TLS connection on the API server."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0027
#   avd_id: AVD-KCV-0027
#   severity: LOW
#   short_code: ensure-tls-cert-file-and-tls-private-key-file-arguments-are-set-as-appropriate
#   recommended_action: "Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the TLS certificate and private key file parameters."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0027

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--tls-cert-file")
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--tls-private-key-file")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate"
	res := result.new(msg, output)
}
