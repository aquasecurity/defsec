package builtin.kubernetes.KCV0014

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0014",
	"avd_id": "AVD-KCV-0014",
	"title": "Ensure that the admission control plugin ServiceAccount is set",
	"short_code": "ensure-admission-control-plugin-service-account-is-set",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Automate service accounts management.",
	"recommended_actions": "Follow the documentation and create ServiceAccount objects as per your environment. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and ensure that the --disable-admission-plugins parameter is set to a value that does not include ServiceAccount.",
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
	regex.match("ServiceAccount", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the admission control plugin ServiceAccount is set"
	res := result.new(msg, output)
}
