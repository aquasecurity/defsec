# METADATA
# title: "Privileged container"
# description: "Privileged containers share namespaces with the host system and do not offer any security. They should be used exclusively for system containers that require high privileges."
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   id: KSV017
#   avd_id: AVD-KSV-0017
#   severity: HIGH
#   short_code: no-privileged-containers
#   recommended_action: "Change 'containers[].securityContext.privileged' to 'false'."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV017

import data.lib.kubernetes
import data.lib.result

default failPrivileged = false

# getPrivilegedContainers returns all containers which have
# securityContext.privileged set to true.
getPrivilegedContainers[container] {
	container := kubernetes.containers[_]
	container.securityContext.privileged == true
}

deny[res] {
	output := getPrivilegedContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.privileged' to false", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
