package builtin.kubernetes.KCV0010

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0010",
	"avd_id": "AVD-KCV-0010",
	"title": "Ensure that the admission control plugin EventRateLimit is set",
	"short_code": "ensure-admission-control-plugin-event-rate-limit-is-set",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Limit the rate at which the API server accepts requests.",
	"recommended_actions": "Follow the Kubernetes documentation and set the desired limits in a configuration file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml and set the below parameters.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--enable-admission-plugins")
}

check_flag[container] {
	container := kubernetes.containers[_]
	some i
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.command[i], -1)
	not regex.match("EventRateLimit", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the admission control plugin EventRateLimit is set"
	res := result.new(msg, output)
}
