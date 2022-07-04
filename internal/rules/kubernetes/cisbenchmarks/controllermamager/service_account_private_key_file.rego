package builtin.kubernetes.KSV0137

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KSV0137",
	"avd_id": "AVD-KSV-0137",
	"title": "Ensure that the --service-account-private-key-file argument is set as appropriate",
	"short_code": "ensure-service-account-private-key-file-argument-is-set-as-appropriate",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Explicitly set a service account private key file for service accounts on the controller manager.",
	"recommended_actions": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --service-account-private-key-file parameter to the private key file for service accounts.",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"component": "kube-controller-manager"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	not regex.match("--service-account-private-key-file", container.command)
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --service-account-private-key-file argument is set as appropriate"
	res := result.new(msg, output)
}
