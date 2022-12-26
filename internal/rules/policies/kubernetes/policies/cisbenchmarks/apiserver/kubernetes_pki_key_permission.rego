# METADATA
# title: "Ensure that the Kubernetes PKI key file permission is set to 600"
# description: "Ensure that the Kubernetes PKI key file permission is set to 600."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0067
#   avd_id: AVD-KCV-0067
#   severity: HIGH
#   short_code: ensure-kubernetes-pki-key-file-permission-set-600.
#   recommended_action: "Change the Kubernetes PKI key file /etc/kubernetes/pki/*.key permission to 600"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0067

import data.lib.kubernetes

validate_pki_key_permission(sp) := {"kubePKIKeyFilePermissions": permission} {
	sp.kind == "NodeInfo"
	sp.type == "master"
	permission := sp.info.kubePKIKeyFilePermissions.values[_]
	permission > 600
}

deny[res] {
	output := validate_pki_key_permission(input)
	msg := "Ensure that the Kubernetes PKI key file permission is set to 600"
	res := result.new(msg, output)
}
