package builtin.kubernetes.KCV0040

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0040",
	"avd_id": "AVD-KCV-0040",
	"title": "Ensure that the --profiling argument is set to false",
	"short_code": "ensure-profiling-argument-is-set-to-false ",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Disable profiling, if not needed.",
	"recommended_actions": "Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml file on the Control Plane node and set the below parameter.",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_scheduler(container)
	not kubernetes.command_has_flag(container.command, "--profiling=false")
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --profiling argument is set to false"
	res := result.new(msg, output)
}
