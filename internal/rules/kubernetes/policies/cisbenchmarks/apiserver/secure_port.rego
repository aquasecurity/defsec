package builtin.kubernetes.KCV0017

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0017",
	"avd_id": "AVD-KCV-0017",
	"title": "Ensure that the --secure-port argument is not set to 0",
	"short_code": "ensure-secure-port-argument-is-not-set-to-0",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Do not disable the secure port.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and either remove the --secure-port parameter or set it to a different (non-zero) desired port.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	kubernetes.command_has_flag(container.command, "--secure-port=0")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --secure-port argument is not set to 0"
	res := result.new(msg, output)
}
