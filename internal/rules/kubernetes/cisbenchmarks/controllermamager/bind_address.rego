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
	"description": "",
	"recommended_actions": "",
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
