package builtin.kubernetes.KCV0030

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0030",
	"avd_id": "AVD-KCV-0030",
	"title": "Ensure that the --encryption-provider-config argument is set as appropriate",
	"short_code": "Ensure that the --encryption-provider-config argument is set as appropriate",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Encrypt etcd key-value store.",
	"recommended_actions": "Follow the Kubernetes documentation and configure a EncryptionConfig file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	kubernetes.command_has_flag(container.command, "--encryption-provider-config")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --encryption-provider-config argument is set as appropriate"
	res := result.new(msg, output)
}
