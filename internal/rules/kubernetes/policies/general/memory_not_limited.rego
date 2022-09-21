# METADATA
# title: "Memory not limited"
# description: "Enforcing memory limits prevents DoS via resource exhaustion."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV018
#   avd_id: AVD-KSV-0018
#   severity: LOW
#   short_code: limit-memory
#   recommended_action: "Set a limit value under 'containers[].resources.limits.memory'."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV018

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

default failLimitsMemory = false

# getLimitsMemoryContainers returns all containers which have set resources.limits.memory
getLimitsMemoryContainers[container] {
	container := kubernetes.containers[_]
	utils.has_key(container.resources.limits, "memory")
}

# getNoLimitsMemoryContainers returns all containers which have not set
# resources.limits.memory
getNoLimitsMemoryContainers[container] {
	container := kubernetes.containers[_]
	not getLimitsMemoryContainers[container]
}

deny[res] {
	output := getNoLimitsMemoryContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'resources.limits.memory'", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
