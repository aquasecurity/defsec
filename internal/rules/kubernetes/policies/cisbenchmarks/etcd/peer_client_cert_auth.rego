# METADATA
# title: "Ensure that the --peer-client-cert-auth argument is set to true"
# description: "etcd should be configured for peer authentication."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KCV0046
#   avd_id: AVD-KCV-0046
#   severity: LOW
#   short_code: ensure-peer-client-cert-auth-argument-is-set-to-true
#   recommended_action: "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0046

import data.lib.kubernetes

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not kubernetes.command_has_flag(container.command, "--peer-client-cert-auth=true")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --peer-client-cert-auth argument is set to true"
	res := result.new(msg, output)
}
