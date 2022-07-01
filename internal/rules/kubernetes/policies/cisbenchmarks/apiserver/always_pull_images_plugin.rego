package builtin.kubernetes.KCV0012

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KSV0012",
	"avd_id": "AVD-KCV-0012",
	"title": "Ensure that the admission control plugin AlwaysPullImages is set",
	"short_code": "ensure-admission-control-plugin-always-pull-images-is-set",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Always pull images.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --enable-admission-plugins parameter to include AlwaysPullImages.",
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
	not regex.match("AlwaysPullImages", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the admission control plugin AlwaysPullImages is set"
	res := result.new(msg, output)
}
