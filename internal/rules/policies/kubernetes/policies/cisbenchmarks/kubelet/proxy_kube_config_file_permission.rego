# METADATA
# title: "If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive"
# description: "If kube-proxy is running, and if it is using a file-based kubeconfig file, ensure that the proxy kubeconfig file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0071
#   avd_id: AVD-KCV-0071
#   severity: HIGH
#   short_code: ensure-proxy-kubeconfig-permissions-set-600-or-more-restrictive-if-exist
#   recommended_action: "Change the proxy kubeconfig file <path><filename> permissions to 600 or more restrictive if exist"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0071

import data.lib.kubernetes

types := ["master", "worker"]

validate_service_file_permission(sp) := {"kubeconfigFileExistsPermissions": permission} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeconfigFileExistsPermissions) > 0
	permission := sp.info.kubeconfigFileExistsPermissions.values[_]
	permission > 600
}

deny[res] {
	output := validate_service_file_permission(input)
	msg := "If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive"
	res := result.new(msg, output)
}
