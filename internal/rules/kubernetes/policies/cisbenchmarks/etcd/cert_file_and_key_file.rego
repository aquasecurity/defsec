package builtin.kubernetes.KCV0042

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0042",
	"avd_id": "AVD-KCV-0042",
	"title": "Ensure that the --cert-file and --key-file arguments are set as appropriate",
	"short_code": "Ensure-cert-file-and-key-file-arguments-are-set-as-appropriate",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Configure TLS encryption for the etcd service.",
	"recommended_actions": "Follow the etcd service documentation and configure TLS encryption. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters.",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not kubernetes.command_has_flag(container.command, "--cert-file")
}

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not kubernetes.command_has_flag(container.command, "--key-file")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --cert-file and --key-file arguments are set as appropriate"
	res := result.new(msg, output)
}
