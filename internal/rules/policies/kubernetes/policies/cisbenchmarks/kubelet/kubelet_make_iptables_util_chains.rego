# METADATA
# title: "Ensure that the --make-iptables-util-chains argument is set to true"
# description: "Allow Kubelet to manage iptables."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0084
#   avd_id: AVD-KCV-0084
#   severity: HIGH
#   short_code: ensure-make-iptables-util-chains-argument-set-true
#   recommended_action: "If using a Kubelet config file, edit the file to set makeIPTablesUtilChains: true"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0084

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_iptables_util_chains_set(sp) := {"kubeletMakeIptablesUtilChainsArgumentSet": iptables_util_chains} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	iptables_util_chains := sp.info.kubeletMakeIptablesUtilChainsArgumentSet.values[_]
	not iptables_util_chains == "true"
}

deny[res] {
	output := validate_kubelet_iptables_util_chains_set(input)
	msg := "Ensure that the --make-iptables-util-chains argument is set to true"
	res := result.new(msg, output)
}
