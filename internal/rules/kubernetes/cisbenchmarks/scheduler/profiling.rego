package builtin.kubernetes.KSV0141

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KSV0141",
	"avd_id": "AVD-KSV-0141",
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
	"selector": [{"component": "kube-scheduler"}],
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
