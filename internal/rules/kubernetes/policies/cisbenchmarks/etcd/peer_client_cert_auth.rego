package builtin.kubernetes.KCV0046

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0046",
	"avd_id": "AVD-KCV-0046",
	"title": "Ensure that the --peer-client-cert-auth argument is set to true",
	"short_code": "ensure-peer-client-cert-auth-argument-is-set-to-true",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "etcd should be configured for peer authentication.",
	"recommended_actions": "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter.",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not kubernetes.command_has_flag(container.command, "--peer-client-cert-auth=true")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --peer-client-cert-auth argument is set to true"
	res := result.new(msg, output)
}
