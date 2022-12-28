# METADATA
# title: "Ensure that the --rotate-certificates argument is not set to false"
# description: "Enable kubelet client certificate rotation."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0090
#   avd_id: AVD-KCV-0090
#   severity: HIGH
#   short_code: ensure-rotate-certificates-argument-set-false
#   recommended_action: "If using a Kubelet config file, edit the file to add the line rotateCertificates: true or remove it altogether to use the default value."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0090

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_rotate_certificates(sp) := {"kubeletRotateCertificatesArgumentSet": rotate_certificates} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	rotate_certificates := sp.info.kubeletRotateCertificatesArgumentSet.values[_]
	rotate_certificates == "false"
}

validate_kubelet_rotate_certificates(sp) := {"kubeletRotateCertificatesArgumentSet": rotate_certificates} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletRotateCertificatesArgumentSet.values) == 0
	rotate_certificates = {}
}

deny[res] {
	output := validate_kubelet_rotate_certificates(input)
	msg := "Ensure that the --rotate-certificates argument is not set to false"
	res := result.new(msg, output)
}
