# METADATA
# title: "Ensure that the controller-manager config  file ownership is set to root:root"
# description: "Ensure that the controller-manager config  file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0065
#   avd_id: AVD-KCV-0065
#   severity: HIGH
#   short_code: ensure-controller-manager-config-ownership-set-root:root.
#   recommended_action: "Change the controller-manager config  file /etc/kubernetes/controller-manager.conf ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0065

import data.lib.kubernetes

validate_conf_ownership(sp) := {"controllerManagerConfFileOwnership": violation} {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {ownership | ownership = sp.info.controllerManagerConfFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny[res] {
	output := validate_conf_ownership(input)
	msg := "Ensure that the controller-manager config file ownership is set to root:root"
	res := result.new(msg, output)
}
