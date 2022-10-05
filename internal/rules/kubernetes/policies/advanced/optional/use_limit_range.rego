# METADATA
# title: "limit range usage"
# description: "ensure limit range policy has configure in order to limit resource usage for namespaces or nodes"
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/
# custom:
#   id: KSV039
#   avd_id: AVD-KSV-0039
#   severity: LOW
#   short_code: limit-range-usage
#   recommended_action: "create limit range policy with a default request and limit, min and max request, for each container."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV039

import data.lib.kubernetes
import data.lib.utils

limitRangeConfigure {
	lower(input.kind) == "limitrange"
	kubernetes.has_field(input.spec, "limits")
	limit := input.spec.limits[_]
	kubernetes.has_field(limit, "type")
	kubernetes.has_field(limit, "max")
	kubernetes.has_field(limit, "min")
	kubernetes.has_field(limit, "default")
	kubernetes.has_field(limit, "defaultRequest")
}

deny[res] {
	not limitRangeConfigure
	msg := "limit range policy with a default request and limit, min and max request, for each container should be configure"
	res := result.new(msg, input.spec)
}
