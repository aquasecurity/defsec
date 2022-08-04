package builtin.kubernetes.KCV0002

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0002",
	"avd_id": "AVD-KCV-0002",
	"title": "Ensure that the --token-auth-file parameter is not set",
	"short_code": "ensure-token-auth-file-parameter-is-not-set",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Do not use token based authentication.",
	"recommended_actions": "Follow the documentation and configure alternate mechanisms for authentication. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --token-auth-file=<filename> parameter.",
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
	regex.match("--token-auth-file", container.command[i])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --token-auth-file parameter is not set"
	res := result.new(msg, output)
}
