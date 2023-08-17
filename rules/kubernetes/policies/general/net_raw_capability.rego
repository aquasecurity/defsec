# METADATA
# title: "NET_RAW capability added"
# description: "The NET_RAW capability grants attackers the ability to eavesdrop on network traffic or generate IP traffic with falsified source addresses, posing serious security risks."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/
# custom:
#   id: KSV119
#   avd_id: AVD-KSV-0119
#   severity: HIGH
#   short_code: no-net-raw
#   recommended_action: "To mitigate potential security risks, it is strongly recommended to remove the NET_RAW capability from 'containers[].securityContext.capabilities.add'. It is advisable to follow the practice of dropping all capabilities and only adding the necessary ones."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV119

import data.lib.kubernetes

default failCapsNetRaw = false

# getCapsNetRaw returns the names of all containers which include
# 'NET_RAW' in securityContext.capabilities.add.
getCapsNetRaw[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.capabilities.add[_] == "NET_RAW"
	container := allContainers.name
}

deny[res] {
	output := getCapsNetRaw[_]
	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should not include 'NET_RAW' in securityContext.capabilities.add", [getCapsNetRaw[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, output)
}
