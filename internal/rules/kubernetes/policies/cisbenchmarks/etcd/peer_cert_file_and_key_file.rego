package builtin.kubernetes.KCV0045

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0045",
	"avd_id": "AVD-KCV-0045",
	"title": "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
	"short_code": "ensure-peer-cert-file-and-peer-key-file-arguments-are-set-as-appropriate",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "etcd should be configured to make use of TLS encryption for peer connections.",
	"recommended_actions": "Follow the etcd service documentation and configure peer TLS encryption as appropriate for your etcd cluster. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters.",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not kubernetes.command_has_flag(container.command, "--peer-cert-file")
}

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not kubernetes.command_has_flag(container.command, "--peer-key-file")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate"
	res := result.new(msg, output)
}
