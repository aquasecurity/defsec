# METADATA
# title: "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate"
# description: "etcd should be configured to make use of TLS encryption for peer connections."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KCV0045
#   avd_id: AVD-KCV-0045
#   severity: LOW
#   short_code: ensure-peer-cert-file-and-peer-key-file-arguments-are-set-as-appropriate
#   recommended_action: "Follow the etcd service documentation and configure peer TLS encryption as appropriate for your etcd cluster. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0045

import data.lib.kubernetes

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not kubernetes.command_has_flag(container.command, "--peer-cert-file")
}

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not kubernetes.command_has_flag(container.command, "--peer-key-file")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate"
	res := result.new(msg, output)
}
