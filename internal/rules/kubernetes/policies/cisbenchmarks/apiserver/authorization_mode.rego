package builtin.kubernetes.KCV0007

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0007",
	"avd_id": "AVD-KCV-0007",
	"title": "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
	"short_code": "ensure-authorization-mode-argument-is-not-set-to-alwaysallow",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Do not always authorize all requests.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --authorization-mode parameter to values other than AlwaysAllow. ",
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
	output := regex.find_all_string_submatch_n(`--authorization-mode=([^\s]+)`, container.command[i], -1)
	regex.match("AlwaysAllow", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --authorization-mode argument is not set to AlwaysAllow"
	res := result.new(msg, output)
}
