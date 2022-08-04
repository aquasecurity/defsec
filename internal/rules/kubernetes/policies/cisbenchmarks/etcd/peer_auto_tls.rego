package builtin.kubernetes.KCV0047

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0047",
	"avd_id": "AVD-KCV-0047",
	"title": "Ensure that the --peer-auto-tls argument is not set to true",
	"short_code": "ensure-peer-auto-tls-argument-is-not-set-to-true",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Do not use self-signed certificates for TLS.",
	"recommended_actions": "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the --peer-auto-tls parameter or set it to false.",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	kubernetes.command_has_flag(container.command, "--peer-auto-tls=true")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --peer-auto-tls argument is not set to true"
	res := result.new(msg, output)
}
