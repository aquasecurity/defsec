package builtin.kubernetes.KCV0015

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0015",
	"avd_id": "AVD-KCV-0015",
	"title": "Ensure that the admission control plugin NamespaceLifecycle is set",
	"short_code": "ensure-admission-control-plugin-namespace-lifecycle-is-set",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Reject creating objects in a namespace that is undergoing termination.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --disable-admission-plugins parameter to ensure it does not include NamespaceLifecycle.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	some i
	output := regex.find_all_string_submatch_n(`--disable-admission-plugins=([^\s]+)`, container.command[i], -1)
	regex.match("NamespaceLifecycle", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the admission control plugin NamespaceLifecycle is set"
	res := result.new(msg, output)
}
