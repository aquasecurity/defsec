package builtin.kubernetes.KSV0142

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KSV0142",
	"avd_id": "AVD-KSV-0142",
	"title": "Ensure that the --bind-address argument is set to 127.0.0.1",
	"short_code": "",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Do not bind the scheduler service to non-loopback insecure addresses.",
	"recommended_actions": "Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml on the Control Plane node and ensure the correct value for the --bind-address parameter.",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"component": "kube-scheduler"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	not regex.match("--bind-address=127.0.0.1", container.command)
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the --bind-address argument is set to 127.0.0.1"
	res := result.new(msg, output)
}
