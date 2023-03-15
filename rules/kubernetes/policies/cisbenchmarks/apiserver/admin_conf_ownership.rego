# METADATA
# title: "Ensure that the admin config  file ownership is set to root:root"
# description: "Ensure that the admin config  file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0061
#   avd_id: AVD-KCV-0061
#   severity: CRITICAL
#   short_code: ensure-admin-config-ownership-set-root:root.
#   recommended_action: "Change the admin config  file /etc/kubernetes/admin.conf ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0061

import data.lib.kubernetes

validate_conf_ownership(sp) := {"adminConfFileOwnership": violation} {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {ownership | ownership = sp.info.adminConfFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny[res] {
	output := validate_conf_ownership(input)
	msg := "Ensure that the admin config  file ownership is set to root:root"
	res := result.new(msg, output)
}
