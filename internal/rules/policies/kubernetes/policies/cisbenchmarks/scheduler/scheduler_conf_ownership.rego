# METADATA
# title: "Ensure that the scheduler config  file ownership is set to root:root"
# description: "Ensure that the scheduler config  file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0063
#   avd_id: AVD-KCV-0063
#   severity: HIGH
#   short_code: ensure-scheduler-config-ownership-set-root:root.
#   recommended_action: "Change the scheduler config  file /etc/kubernetes/scheduler.conf ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0063

import data.lib.kubernetes

validate_conf_ownership(sp) := {"schedulerConfFileOwnership": ownership} {
	sp.kind == "NodeInfo"
	sp.type == "master"
	ownership := sp.info.schedulerConfFileOwnership.values[_]
	not ownership == "root:root"
}

deny[res] {
	output := validate_conf_ownership(input)
	msg := "Ensure that the scheduler config  file ownership is set to root:root"
	res := result.new(msg, output)
}
