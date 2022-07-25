package builtin.kubernetes.KCV0021

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0021",
	"avd_id": "AVD-KCV-0021",
	"title": "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate",
	"short_code": "ensure-audit-log-maxbackup-argument-is-set-to-10-or-as-appropriate",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Retain 10 or an appropriate number of old log files.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxbackup parameter to 10 or to an appropriate value.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--audit-log-maxbackup")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate"
	res := result.new(msg, output)
}
