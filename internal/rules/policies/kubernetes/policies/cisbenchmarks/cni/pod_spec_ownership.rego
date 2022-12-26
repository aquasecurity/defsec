# METADATA
# title: "Ensure that the container network interface file ownership is set to root:root"
# description: "Ensure that the container network interface file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0057
#   avd_id: AVD-KCV-0057
#   severity: HIGH
#   short_code: ensure-container-network-interface-ownership-set-root:root.
#   recommended_action: "Change the container network interface file path/to/cni/files ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0057

import data.lib.kubernetes

validate_spec_ownership(sp) := {"containerNetworkInterfaceFileOwnership": ownership} {
	sp.kind == "NodeInfo"
	sp.type == "master"
	ownership := sp.info.containerNetworkInterfaceFileOwnership[_]
	not ownership == "root:root"
}

deny[res] {
	output := validate_spec_ownership(input)
	msg := "Ensure that the container network interface file ownership is set to root:root"
	res := result.new(msg, output)
}
