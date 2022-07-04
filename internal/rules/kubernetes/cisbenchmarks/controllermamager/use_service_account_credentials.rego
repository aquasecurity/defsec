package builtin.kubernetes.KSV0136

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KSV0136",
	"avd_id": "AVD-KSV-0136",
	"title": "Ensure that the --use-service-account-credentials argument is set to true",
	"short_code": "ensure-use-service-account-credentials-argument-is-set-to-true",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Use individual service account credentials for each controller.",
	"recommended_actions": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node to set the below parameter.",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"component": "kube-controller-manager"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	not regex.match("--use-service-account-credentials=true", container.command)
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --use-service-account-credentials argument is set to true"
	res := result.new(msg, output)
}
