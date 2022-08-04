package builtin.kubernetes.KCV0003

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0003",
	"avd_id": "AVD-KCV-0003",
	"title": "Ensure that the --DenyServiceExternalIPs is not set",
	"short_code": "Ensure-deny-service-external-ips-is-not-set",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "This admission controller rejects all net-new usage of the Service field externalIPs.",
	"recommended_actions": "Edit the API server pod specification file $apiserverconf on the control plane node and remove the `DenyServiceExternalIPs` from enabled admission plugins.",
	"url": "https://www.cisecurity.org/benchmark/kubernetes",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

check_flag[container] {
	container := kubernetes.containers[_]
	some i
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.command[i], -1)
	regex.match("DenyServiceExternalIPs", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --DenyServiceExternalIPs is not set"
	res := result.new(msg, output)
}
