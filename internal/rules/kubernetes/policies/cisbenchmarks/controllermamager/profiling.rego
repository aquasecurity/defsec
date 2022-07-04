package builtin.kubernetes.KCV0034

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0034",
	"avd_id": "AVD-KCV-0034",
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
	"selector": [{"type": "kubernetes"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_controllermananager(container)
	not kubernetes.command_has_flag(container.command, "--profiling=false")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --profiling argument is set to false"
	res := result.new(msg, output)
}
