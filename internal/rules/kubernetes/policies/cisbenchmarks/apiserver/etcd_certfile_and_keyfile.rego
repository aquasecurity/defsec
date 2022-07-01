package builtin.kubernetes.KCV0026

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0026",
	"avd_id": "AVD-KCV-0026",
	"title": "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
	"short_code": "ensure-etcd-certfile-and-etcd-keyfile-arguments-are-set-as-appropriate",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "etcd should be configured to make use of TLS encryption for client connections.",
	"recommended_actions": "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the etcd certificate and key file parameters.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--etcd-certfile")
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--etcd-keyfile")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate"
	res := result.new(msg, output)
}
