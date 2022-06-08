package builtin.kubernetes.KSV103

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV103",
	"avd_id": "AVD-KSV-0103",
	"title": "HostProcess container defined",
	"short_code": "no-hostprocess-containers",
	"severity": "MEDIUM",
	"description": "Windows pods offer the ability to run HostProcess containers which enable privileged access to the Windows node.",
	"recommended_actions": "Do not enable 'hostProcess' on any securityContext",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

failHostProcess[spec] {
	spec := input.spec
	spec.securityContext.windowsOptions.hostProcess == true
}

failHostProcess[options] {
	container := kubernetes.containers[_]
	options := container.securityContext.windowsOptions
	options.hostProcess == true
}

deny[res] {
	cause := failHostProcess[_]
	msg := "You should not enable hostProcess."
	res := result.new(msg, cause)
}
