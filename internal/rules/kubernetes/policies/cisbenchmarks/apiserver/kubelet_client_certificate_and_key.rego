package builtin.kubernetes.KCV0005

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0005",
	"avd_id": "AVD-KCV-0005",
	"title": "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
	"short_code": "ensure-kubelet-client-certificate-and-kubelet-client-key-are-set",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Enable certificate based kubelet authentication.",
	"recommended_actions": "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and kubelets.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--kubelet-client-certificate")
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--kubelet-client-key")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate"
	res := result.new(msg, output)
}
