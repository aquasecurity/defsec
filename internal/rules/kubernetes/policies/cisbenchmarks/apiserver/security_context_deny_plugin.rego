package builtin.kubernetes.KCV0013

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KCV0013",
	"avd_id": "AVD-KCV-0013",
	"title": "Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used",
	"short_code": "ensure-admission-control-plugin-security-context-deny-is-set-if-pod-security-policy-is-not-used",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "The SecurityContextDeny admission controller can be used to deny pods which make use of some SecurityContext fields which could allow for privilege escalation in the cluster. This should be used where PodSecurityPolicy is not in place within the cluster.",
	"recommended_actions": "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --enable-admission-plugins parameter to include SecurityContextDeny, unless PodSecurityPolicy is already in place.",
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
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.command[i], -1)
	not regex.match("PodSecurityPolicy", output[0][1])
	not regex.match("SecurityContextDeny", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used"
	res := result.new(msg, output)
}
