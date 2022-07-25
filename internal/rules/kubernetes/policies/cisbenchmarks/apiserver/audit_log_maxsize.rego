package builtin.kubernetes.KCV0022

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0022",
	"avd_id": "AVD-KCV-0022",
	"title": "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate",
	"short_code": "ensure-audit-log-maxsize-argument-is-set-to-100-or-as-appropriate",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Rotate log files on reaching 100 MB or as appropriate.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxsize parameter to an appropriate size in MB",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--audit-log-maxsize")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate"
	res := result.new(msg, output)
}
