# METADATA
# title: "Ensure that the scheduler config file permissions are set to 600 or more restrictive"
# description: "Ensure that the scheduler config file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0062
#   avd_id: AVD-KCV-0062
#   severity: HIGH
#   short_code: ensure-scheduler-config-file-permissions-set-600-or-more-restrictive
#   recommended_action: "Change the scheduler config file /etc/kubernetes/scheduler.conf permissions of 600 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0062

import data.lib.kubernetes

validate_conf_permission(sp) := {"schedulerConfFilePermissions": violation} {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {permission | permission = sp.info.schedulerConfFilePermissions.values[_]; permission > 600}
	count(violation) > 0
}

deny[res] {
	output := validate_conf_permission(input)
	msg := "Ensure that the scheduler config file permissions is set to 600 or more restrictive"
	res := result.new(msg, output)
}
