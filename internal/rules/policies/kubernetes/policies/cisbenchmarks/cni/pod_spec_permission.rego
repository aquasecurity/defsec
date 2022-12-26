# METADATA
# title: "Ensure that the container network interface file permissions are set to 600 or more restrictive"
# description: "Ensure that the container network interface file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0056
#   avd_id: AVD-KCV-0056
#   severity: HIGH
#   short_code: ensure-container-network-interface-file-permissions-set-600-or-more-restrictive
#   recommended_action: "Change the container network interface file path/to/cni/files permissions of 600 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0056

import data.lib.kubernetes

validate_cni_permission(sp) := {"containerNetworkInterfaceFilePermissions": permission} {
	sp.kind == "NodeInfo"
	sp.type == "master"
	permission := sp.info.containerNetworkInterfaceFilePermissions[_]
	permission > 600
}

deny[res] {
	output := validate_cni_permission(input)
	msg := "Ensure that the Container Network Interface specification file permissions is set to 600 or more restrictive"
	res := result.new(msg, output)
}
