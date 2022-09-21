# METADATA
# title: "Ensure that the --client-cert-auth argument is set to true"
# description: "Enable client authentication on etcd service."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KCV0043
#   avd_id: AVD-KCV-0043
#   severity: LOW
#   short_code: ensure-client-cert-auth-argument-is-set-to-true
#   recommended_action: "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0043

import data.lib.kubernetes
import data.lib.result

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not kubernetes.command_has_flag(container.command, "--client-cert-auth=true")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --client-cert-auth argument is set to true"
	res := result.new(msg, output)
}
