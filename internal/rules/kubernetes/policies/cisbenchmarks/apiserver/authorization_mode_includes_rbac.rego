package builtin.kubernetes.KCV0009

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0009",
	"avd_id": "AVD-KCV-0009",
	"title": "Ensure that the --authorization-mode argument includes RBAC",
	"short_code": "ensure-authorization-mode-argument-includes-rbac",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Turn on Role Based Access Control.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --authorization-mode parameter to a value that includes RBAC.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--authorization-mode")
}

check_flag[container] {
	container := kubernetes.containers[_]
	some i
	output := regex.find_all_string_submatch_n(`--authorization-mode=([^\s]+)`, container.command[i], -1)
	not regex.match("RBAC", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --authorization-mode argument includes RBAC"
	res := result.new(msg, output)
}
