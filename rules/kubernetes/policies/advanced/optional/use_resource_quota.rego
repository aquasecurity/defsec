# METADATA
# title: "resource quota usage"
# description: "ensure resource quota policy has configure in order to limit aggregate resource usage within namespace"
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/quota-memory-cpu-namespace/
# custom:
#   id: KSV040
#   avd_id: AVD-KSV-0040
#   severity: LOW
#   short_code: resource-quota-usage
#   recommended_action: "create resource quota policy with mem and cpu quota per each namespace"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV040

import data.lib.kubernetes
import data.lib.utils

resourceQuotaConfigure {
	lower(input.kind) == "resourcequota"
	input.spec[hard]
	kubernetes.has_field(input.spec.hard, "requests.cpu")
	kubernetes.has_field(input.spec.hard, "requests.memory")
	kubernetes.has_field(input.spec.hard, "limits.cpu")
	kubernetes.has_field(input.spec.hard, "limits.memory")
}

deny[res] {
	not resourceQuotaConfigure
	msg := "resource quota policy with hard memory and cpu quota per namespace should be configure"
	res := result.new(msg, object.get(input.spec, "hard", input.spec))
}
