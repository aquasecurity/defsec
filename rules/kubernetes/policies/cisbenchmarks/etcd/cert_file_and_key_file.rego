# METADATA
# title: "Ensure that the --cert-file and --key-file arguments are set as appropriate"
# description: "Configure TLS encryption for the etcd service."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0042
#   avd_id: AVD-KCV-0042
#   severity: LOW
#   short_code: Ensure-cert-file-and-key-file-arguments-are-set-as-appropriate
#   recommended_action: "Follow the etcd service documentation and configure TLS encryption. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0042

import data.lib.kubernetes

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not kubernetes.command_has_flag(container.command, "--cert-file")
}

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not kubernetes.command_has_flag(container.command, "--key-file")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --cert-file and --key-file arguments are set as appropriate"
	res := result.new(msg, output)
}
