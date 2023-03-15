# METADATA
# title: "Ensure that the admission control plugin AlwaysPullImages is set"
# description: "Always pull images."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KSV0012
#   avd_id: AVD-KCV-0012
#   severity: LOW
#   short_code: ensure-admission-control-plugin-always-pull-images-is-set
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --enable-admission-plugins parameter to include AlwaysPullImages."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0012

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--enable-admission-plugins")
}

check_flag[container] {
	container := kubernetes.containers[_]
	some i
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.command[i], -1)
	not regex.match("AlwaysPullImages", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the admission control plugin AlwaysPullImages is set"
	res := result.new(msg, output)
}
