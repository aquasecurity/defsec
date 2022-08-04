package builtin.kubernetes.KCV0001

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0001",
	"avd_id": "AVD-KCV-0001",
	"title": "Ensure that the --anonymous-auth argument is set to false",
	"short_code": "ensure-anonymous-auth-argument-is-false",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Disable anonymous requests to the API server.",
	"recommended_actions": "Set '--anonymous-auth' to 'false'.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	some i
	flag := container.command[i]
	not kubernetes.command_has_flag(container.command, "--anonymous-auth=false")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --anonymous-auth argument is set to false"
	res := result.new(msg, output)
}
