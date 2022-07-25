package builtin.kubernetes.KCV0019

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0019",
	"avd_id": "AVD-KCV-0019",
	"title": "Ensure that the --audit-log-path argument is set",
	"short_code": "ensure-audit-log-path-argument-is-set",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Enable auditing on the Kubernetes API Server and set the desired audit log path.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-path parameter.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--audit-log-path")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --audit-log-path argument is set"
	res := result.new(msg, output)
}
