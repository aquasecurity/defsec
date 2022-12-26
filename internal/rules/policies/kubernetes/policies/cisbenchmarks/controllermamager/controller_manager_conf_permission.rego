# METADATA
# title: "Ensure that the controller-manager config file permissions are set to 600 or more restrictive"
# description: "Ensure that the controller-manager config file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0064
#   avd_id: AVD-KCV-0064
#   severity: HIGH
#   short_code: ensure-controller-manager-config-file-permissions-set-600-or-more-restrictive
#   recommended_action: "Change the controller manager config file /etc/kubernetes/controller-manager.conf permissions of 600 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0064

import data.lib.kubernetes

validate_conf_permission(sp) := {"controllerManagerConfFilePermissions": permission} {
	sp.kind == "NodeInfo"
	sp.type == "master"
	permission := sp.info.controllerManagerConfFilePermissions[_]
	permission > 600
}

deny[res] {
	output := validate_conf_permission(input)
	msg := "Ensure that the controller-manager config file permissions is set to 600 or more restrictive"
	res := result.new(msg, output)
}
