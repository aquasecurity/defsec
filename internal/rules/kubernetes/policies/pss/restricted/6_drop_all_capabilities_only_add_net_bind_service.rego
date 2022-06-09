package builtin.kubernetes.KSV106

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV106",
	"avd_id": "AVD-KSV-0106",
	"title": "Container capabilities must only include NET_BIND_SERVICE",
	"short_code": "drop-caps-add-bind-svc",
	"severity": "LOW",
	"description": "Containers must drop ALL capabilities, and are only permitted to add back the NET_BIND_SERVICE capability.",
	"recommended_actions": "Set 'spec.containers[*].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers[*].securityContext.capabilities.add'.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

hasDropAll(container) {
	container.securityContext.capabilities.drop[_] == "ALL"
}

containersWithoutDropAll[container] {
	container := kubernetes.containers[_]
	not hasDropAll(container)
}

containersWithDropAll[container] {
	container := kubernetes.containers[_]
	hasDropAll(container)
}

deny[res] {
	container := containersWithoutDropAll[_]
	msg := "container should drop all"
	res := result.new(msg, container)
}

deny[res] {
	container := containersWithDropAll[_]
	add := container.securityContext.capabilities.add[_]
	add != "NET_BIND_SERVICE"
	msg := "container should not add stuff"
	res := result.new(msg, container.securityContext.capabilities)
}
