package builtin.kubernetes.KSV105

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV105",
	"avd_id": "AVD-KSV-0105",
	"title": "Containers must not set runAsUser to 0",
	"short_code": "containers-not-run-as-root",
	"severity": "LOW",
	"description": "Containers should be forbidden from running with a root UID.",
	"recommended_actions": "Set 'securityContext.runAsUser' to a non-zero integer or leave undefined.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

failRootUserId[securityContext] {
	container := kubernetes.containers[_]
	securityContext := container.securityContext
	securityContext.runAsUser == 0
}

failRootUserId[securityContext] {
	pod := kubernetes.pods[_]
	securityContext := pod.spec.securityContext
	securityContext.runAsUser == 0
}

deny[res] {
	cause := failRootUserId[_]
	msg := "securityContext.runAsUser should be set to a value greater than 0"
	res := result.new(msg, cause)
}
