# METADATA
# title: "Ensure that the kubelet service file permissions are set to 600 or more restrictive"
# description: "Ensure that the kubelet service file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0069
#   avd_id: AVD-KCV-0069
#   severity: HIGH
#   short_code: ensure-kubelet-service-file-permissions-set-600-or-more-restrictive
#   recommended_action: "Change the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf permissions of 600 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0069

import data.lib.kubernetes

types := ["master", "worker"]

validate_service_file_permission(sp) := {"kubeletServiceFilePermissions": violation} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {permission | permission = sp.info.kubeletServiceFilePermissions.values[_]; permission > 600}
	count(violation) > 0
}

deny[res] {
	output := validate_service_file_permission(input)
	msg := "Ensure that the kubelet service file permissions are set to 600 or more restrictive"
	res := result.new(msg, output)
}
