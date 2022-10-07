# METADATA
# title: "Ensure that the --encryption-provider-config argument is set as appropriate"
# description: "Encrypt etcd key-value store."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0030
#   avd_id: AVD-KCV-0030
#   severity: LOW
#   short_code: Ensure that the --encryption-provider-config argument is set as appropriate
#   recommended_action: "Follow the Kubernetes documentation and configure a EncryptionConfig file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0030

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	kubernetes.command_has_flag(container.command, "--encryption-provider-config")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --encryption-provider-config argument is set as appropriate"
	res := result.new(msg, output)
}
