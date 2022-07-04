package builtin.kubernetes.KSV0138

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KSV0138",
	"avd_id": "AVD-KSV-0138",
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
	"selector": [{"component": "kube-controller-manager"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	not regex.match("--root-ca-file", container.command)
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --root-ca-file argument is set as appropriate"
	res := result.new(msg, output)
}
