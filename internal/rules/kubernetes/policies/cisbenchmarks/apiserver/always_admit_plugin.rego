# METADATA
# title: "Ensure that the admission control plugin AlwaysAdmit is not set"
# description: "Do not allow all requests."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KCV0011
#   avd_id: AVD-KCV-0011
#   severity: LOW
#   short_code: ensure-admission-control-plugin-always-admit-is-not-set
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and either remove the --enable-admission- plugins parameter, or set it to a value that does not include AlwaysAdmit."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0011

import data.lib.kubernetes
import data.lib.result

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	some i
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.command[i], -1)
	regex.match("AlwaysAdmit", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the admission control plugin AlwaysAdmit is not set"
	res := result.new(msg, output)
}
