# METADATA
# title: "Ensure that the --client-ca-file argument is set as appropriate"
# description: "Enable Kubelet authentication using certificates."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0081
#   avd_id: AVD-KCV-0081
#   severity: HIGH
#   short_code: ensure-client-ca-argument-set-appropriate
#   recommended_action: "If using a Kubelet config file, edit  the --client-ca-file argument ito appropriate value"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0081

import data.lib.kubernetes

types := ["master", "worker"]

validate_client_ca_set(sp) := {"kubeletClientCaFileArgumentSet": client_ca} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	client_ca := sp.info.kubeletClientCaFileArgumentSet.values[_]
	client_ca == ""
}

validate_client_ca_set(sp) := {"kubeletClientCaFileArgumentSet": client_ca} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletClientCaFileArgumentSet.values) == 0
	client_ca = {}
}

deny[res] {
	output := validate_client_ca_set(input)
	msg := "Ensure that the --client-ca-file argument is set as appropriate"
	res := result.new(msg, output)
}
