package builtin.kubernetes.KCV0018

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0018",
	"avd_id": "AVD-KCV-0018",
	"title": "Ensure that the --profiling argument is set to false",
	"short_code": "ensure-profiling-argument-is-set-to-false",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Disable profiling, if not needed.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the below parameter.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--profiling=false")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --profiling argument is set to false"
	res := result.new(msg, output)
}
