package builtin.kubernetes.KSV0139

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KSV0139",
	"avd_id": "AVD-KSV-0139",
	"title": "Ensure that the RotateKubeletServerCertificate argument is set to true",
	"short_code": "Ensure that the RotateKubeletServerCertificate argument is set to true",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Enable kubelet server certificate rotation on controller-manager.",
	"recommended_actions": "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --feature-gates parameter to include RotateKubeletServerCertificate=true .",
	"url": "<cisbench>",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"component": "kube-controller-manager"}],
}

checkFlag[container] {
	container := kubernetes.containers[_]
	not regex.match("RotateKubeletServerCertificate=true", container.command)
}

deny[res] {
	output := checkFlag[_]
	msg := "Ensure that the RotateKubeletServerCertificate argument is set to true"
	res := result.new(msg, output)
}
