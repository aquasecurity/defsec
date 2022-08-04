package builtin.kubernetes.KCV0006

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0006",
	"avd_id": "AVD-KCV-0006",
	"title": "Ensure that the --kubelet-certificate-authority argument is set as appropriate",
	"short_code": "ensure-kubelet-certificate-authority-argument-is-set",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Verify kubelet's certificate before establishing connection.",
	"recommended_actions": "Follow the Kubernetes documentation and setup the TLS connection between the apiserver and kubelets. ",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--kubelet-certificate-authority")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --kubelet-certificate-authority argument is set as appropriate"
	res := result.new(msg, output)
}
