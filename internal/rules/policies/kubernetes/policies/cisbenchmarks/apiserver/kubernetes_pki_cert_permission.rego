# METADATA
# title: "Ensure that the Kubernetes PKI certificate file permission is set to 600"
# description: "Ensure that the Kubernetes PKI certificate file permission is set to 600."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0068
#   avd_id: AVD-KCV-0068
#   severity: HIGH
#   short_code: ensure-kubernetes-pki-cert-file-permission-set-600.
#   recommended_action: "Change the Kubernetes PKI certificate file /etc/kubernetes/pki/*.crt permission to 600"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0068

import data.lib.kubernetes

validate_pki_cert_permission(sp) := {"KubernetesPKICertificateFilePermissions": permission} {
	sp.kind == "Nodeinfo"
	sp.type == "master"
	permission := sp.info.KubernetesPKICertificateFilePermissions[_]
	permission > 600
}

deny[res] {
	output := validate_pki_cert_permission(input)
	msg := "Ensure that the Kubernetes PKI certificate file permission is set to 600"
	res := result.new(msg, output)
}
