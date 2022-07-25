package builtin.kubernetes.KCV0004

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0004",
	"avd_id": "AVD-KCV-0004",
	"title": "Ensure that the --kubelet-https argument is set to true",
	"short_code": "ensure-kubelet-https-argument-is-set-to-true",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Use https for kubelet connections.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and remove the --kubelet-https parameter.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	kubernetes.command_has_flag(container.command, "--kubelet-https=false")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --kubelet-https argument is set to true"
	res := result.new(msg, output)
}
