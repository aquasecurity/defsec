# METADATA
# title: "Ensure that the --auto-tls argument is not set to true"
# description: "Do not use self-signed certificates for TLS."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0044
#   avd_id: AVD-KCV-0044
#   severity: LOW
#   short_code: ensure-auto-tls-argument-is-not-set-to-true
#   recommended_action: "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the --auto-tls parameter or set it to false."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0044

import data.lib.kubernetes

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	kubernetes.command_has_flag(container.command, "--auto-tls=true")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --auto-tls argument is not set to true"
	res := result.new(msg, output)
}
