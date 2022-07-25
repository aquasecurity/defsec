package builtin.kubernetes.KCV0025

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0025",
	"avd_id": "AVD-KCV-0025",
	"title": "Ensure that the --service-account-key-file argument is set as appropriate",
	"short_code": "ensure-service-account-key-file-argument-is-set-as-appropriate",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Explicitly set a service account public key file for service accounts on the apiserver.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --service-account-key-file parameter to the public key file for service accounts.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--service-account-key-file")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --service-account-key-file argument is set as appropriate"
	res := result.new(msg, output)
}
