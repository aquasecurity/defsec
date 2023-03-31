# METADATA
# title: "Ensure that the kubelet service file ownership is set to root:root"
# description: "Ensure that the kubelet service file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0070
#   avd_id: AVD-KCV-0070
#   severity: CRITICAL
#   short_code: ensure-kubelet-service-file-ownership-set-root:root.
#   recommended_action: "Change the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0070

import data.lib.kubernetes

types := ["master", "worker"]

validate_service_file_ownership(sp) := {"kubeletServiceFileOwnership": violation} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {ownership | ownership = sp.info.kubeletServiceFileOwnership.values[_]; ownership != "root:root"}
	count(violation) > 0
}

deny[res] {
	output := validate_service_file_ownership(input)
	msg := "Ensure that the kubelet service file ownership is set to root:root"
	res := result.new(msg, output)
}
