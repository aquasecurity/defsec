# METADATA
# title: "Runtime/Default AppArmor profile not set"
# description: "A program inside the container can bypass AppArmor protection policies."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV002
#   avd_id: AVD-KSV-0002
#   severity: MEDIUM
#   short_code: use-default-apparmor-profile
#   recommended_action: "Remove 'container.apparmor.security.beta.kubernetes.io' annotation or set it to 'runtime/default'."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV002

import data.lib.kubernetes

default failAppArmor = false

apparmor_keys[container] = key {
	container := kubernetes.containers[_]
	key := sprintf("%s/%s", ["container.apparmor.security.beta.kubernetes.io", container.name])
}

custom_apparmor_containers[container] {
	key := apparmor_keys[container]
	annotations := kubernetes.annotations[_]
	val := annotations[key]
	val != "runtime/default"
}

deny[res] {
	output := custom_apparmor_containers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should specify an AppArmor profile", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
