# METADATA
# title: "Ensure that the admin config file permissions are set to 600 or more restrictive"
# description: "Ensure that the admin config file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0060
#   avd_id: AVD-KCV-0060
#   severity: HIGH
#   short_code: ensure-admin-config-file-permissions-set-600-or-more-restrictive
#   recommended_action: "Change the admin config file /etc/kubernetes/admin.conf permissions of 600 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0060

import data.lib.kubernetes

validate_conf_permission(sp) := {"AdminConfFilePermissions": permission} {
	sp.kind == "Nodeinfo"
	sp.type == "master"
	permission := sp.info.AdminConfFilePermissions[_]
	permission > 600
}

deny[res] {
	output := validate_conf_permission(input)
	msg := "Ensure that the admin config file permissions is set to 600 or more restrictive"
	res := result.new(msg, output)
}
