# METADATA
# title: "Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root"
# description: "Ensure that the kubelet.conf file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0074
#   avd_id: AVD-KCV-0074
#   severity: HIGH
#   short_code: ensure-kubeconfig-kubelet.conf-ownership-set-root:root
#   recommended_action: "Change the --kubeconfig kubelet.conf file ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0074

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_file_ownership(sp) := {"kubeletConfFileOwnership": violation} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {ownership | ownership = sp.info.kubeletConfFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny[res] {
	output := validate_kubelet_file_ownership(input)
	msg := "Ensure that the kubelet.conf file ownership is set to root:root."
	res := result.new(msg, output)
}
