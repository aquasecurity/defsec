package builtin.kubernetes.KSV0135

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KSV0135",
	"avd_id": "AVD-KSV-0135",
	"title": "Ensure that the --profiling argument is set to false",
	"short_code": "ensure-profiling-argument-is-set-to-false ",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Disable profiling, if not needed.",
	"recommended_actions": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the below parameter.",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"component": "kube-controller-manager"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	not regex.match("--profiling=false", container.command)
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --profiling argument is set to false"
	res := result.new(msg, output)
}
