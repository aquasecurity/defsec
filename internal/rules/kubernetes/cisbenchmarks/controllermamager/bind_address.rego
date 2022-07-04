package builtin.kubernetes.KSV0140

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KSV0140",
	"avd_id": "AVD-KSV-0140",
	"title": "Ensure that the --bind-address argument is set to 127.0.0.1",
	"short_code": "",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Do not bind the scheduler service to non-loopback insecure addresses.",
	"recommended_actions": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and ensure the correct value for the --bind-address parameter",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"component": "kube-controller-manager"}],
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
