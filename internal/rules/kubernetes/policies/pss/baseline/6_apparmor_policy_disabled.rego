package builtin.kubernetes.KSV002

import data.lib.kubernetes
import data.lib.result

default failAppArmor = false

__rego_metadata__ := {
	"id": "KSV002",
	"avd_id": "AVD-KSV-0002",
	"title": "Default AppArmor profile not set",
	"short_code": "use-default-apparmor-profile",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "A program inside the container can bypass AppArmor protection policies.",
	"recommended_actions": "Remove 'container.apparmor.security.beta.kubernetes.io' annotation or set it to 'runtime/default'.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

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
