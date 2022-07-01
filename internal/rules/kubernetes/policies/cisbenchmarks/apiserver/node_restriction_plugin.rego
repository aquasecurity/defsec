package builtin.kubernetes.KCV0016

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0016",
	"avd_id": "AVD-KCV-0016",
	"title": "Ensure that the admission control plugin NodeRestriction is set",
	"short_code": "ensure-admission-control-plugin-node-restriction-is-set",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Limit the Node and Pod objects that a kubelet could modify.",
	"recommended_actions": "Follow the Kubernetes documentation and configure NodeRestriction plug-in on kubelets. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to a value that includes NodeRestriction.",
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
	not regex.match("NodeRestriction", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the admission control plugin NodeRestriction is set"
	res := result.new(msg, output)
}
