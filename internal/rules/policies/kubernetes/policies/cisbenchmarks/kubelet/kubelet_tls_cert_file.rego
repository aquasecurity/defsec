# METADATA
# title: "Ensure that the --tls-cert-file argument are set as appropriate"
# description: "Setup TLS connection on the Kubelets."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0088
#   avd_id: AVD-KCV-0088
#   severity: HIGH
#   short_code: ensure-tls-cert-file-argument-set-appropriate
#   recommended_action: "If using a Kubelet config file, edit the file to set tlsCertFile to the location"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0088

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_tls_cert_file(sp) := {"kubeletTlsCertFileTlsArgumentSet": tls_cert_file} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	tls_cert_file := sp.info.kubeletTlsCertFileTlsArgumentSet.values[_]
	not endswith(tls_cert_file, ".crt")
}

validate_kubelet_tls_cert_file(sp) := {"kubeletTlsCertFileTlsArgumentSet": tls_cert_file} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletTlsCertFileTlsArgumentSet.values) == 0
	tls_cert_file := {}
}

deny[res] {
	output := validate_kubelet_tls_cert_file(input)
	msg := "Ensure that the --tls-cert-file argument are set as appropriate"
	res := result.new(msg, output)
}
