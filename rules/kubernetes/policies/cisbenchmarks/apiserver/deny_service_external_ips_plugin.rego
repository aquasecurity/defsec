# METADATA
# title: "Ensure that the --DenyServiceExternalIPs is not set"
# description: "This admission controller rejects all net-new usage of the Service field externalIPs."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0003
#   avd_id: AVD-KCV-0003
#   severity: LOW
#   short_code: Ensure-deny-service-external-ips-is-not-set
#   recommended_action: "Edit the API server pod specification file $apiserverconf on the control plane node and remove the `DenyServiceExternalIPs` from enabled admission plugins."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0003

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	some i
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.command[i], -1)
	regex.match("DenyServiceExternalIPs", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --DenyServiceExternalIPs is not set"
	res := result.new(msg, output)
}
