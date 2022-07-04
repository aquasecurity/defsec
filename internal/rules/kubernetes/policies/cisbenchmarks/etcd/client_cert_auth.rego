package builtin.kubernetes.KCV0043

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0043",
	"avd_id": "AVD-KCV-0043",
	"title": "Ensure that the --client-cert-auth argument is set to true",
	"short_code": "ensure-client-cert-auth-argument-is-set-to-true",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Enable client authentication on etcd service.",
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
	not kubernetes.command_has_flag(container.command, "--client-cert-auth=true")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --client-cert-auth argument is set to true"
	res := result.new(msg, output)
}
