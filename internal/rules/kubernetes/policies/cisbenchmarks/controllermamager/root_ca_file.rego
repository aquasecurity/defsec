package builtin.kubernetes.KCV0037

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0037",
	"avd_id": "AVD-KCV-0037",
	"title": "Ensure that the --root-ca-file argument is set as appropriate",
	"short_code": "ensure-root-ca-file-argument-is-set-as-appropriate",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Allow pods to verify the API server's serving certificate before establishing connections.",
	"recommended_actions": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --root-ca-file parameter to the certificate bundle file`.",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_controllermananager(container)
	not kubernetes.command_has_flag(container.command, "--root-ca-file")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --root-ca-file argument is set as appropriate"
	res := result.new(msg, output)
}
