# METADATA
# title: "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive"
# description: "Ensure that the kubelet.conf file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0073
#   avd_id: AVD-KCV-0073
#   severity: HIGH
#   short_code: ensure-kubelet.conf-file-permissions-600-or-more-restrictive.
#   recommended_action: "Change the kubelet.conf file permissions to 600 or more restrictive if exist"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0073

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_file_permission(sp) := {"kubeletConfFilePermissions": violation} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {permission | permission = sp.info.kubeletConfFilePermissions.values[_]; permission > 600}
	count(violation) > 0
}

deny[res] {
	output := validate_kubelet_file_permission(input)
	msg := "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive"
	res := result.new(msg, output)
}
