package builtin.kubernetes.KSV0134

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KSV0134",
	"avd_id": "AVD-KSV-0134",
	"title": "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate",
	"short_code": "ensure-terminated-pod-gc-threshold-argument-is-set-as-appropriate",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Activate garbage collector on pod termination, as appropriate.",
	"recommended_actions": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --terminated-pod-gc-threshold to an appropriate threshold.",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"component": "kube-controller-manager"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	not regex.match("--terminated-pod-gc-threshold", container.command)
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate"
	res := result.new(msg, output)
}
