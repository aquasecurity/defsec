# METADATA
# title: "Ensure that the --tls-key-file argument are set as appropriate"
# description: "Setup TLS connection on the Kubelets."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0089
#   avd_id: AVD-KCV-0089
#   severity: CRITICAL
#   short_code: ensure-tls-key-file-argument-set-appropriate
#   recommended_action: "If using a Kubelet config file, edit the file to set tlskeyFile to the location"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0089

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_tls_key_file(sp) := {"kubeletTlsPrivateKeyFileArgumentSet": violation} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {tls_key_file | tls_key_file = sp.info.kubeletTlsPrivateKeyFileArgumentSet.values[_]; not endswith(tls_key_file, ".key")}
	count(violation) > 0
}

validate_kubelet_tls_key_file(sp) := {"kubeletTlsPrivateKeyFileArgumentSet": tls_key_file} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletTlsPrivateKeyFileArgumentSet.values) == 0
	tls_key_file := {}
}

deny[res] {
	output := validate_kubelet_tls_key_file(input)
	msg := "Ensure that the --tls-key-file argument are set as appropriate"
	res := result.new(msg, output)
}
