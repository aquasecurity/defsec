# METADATA
# title: "if proxy kubeconfig file exists ensure ownership is set to root:root"
# description: "If kube-proxy is running, ensure that the file ownership of its kubeconfig file is set to root:root."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0072
#   avd_id: AVD-KCV-0072
#   severity: HIGH
#   short_code: ensure-proxy-kubeconfig-ownership-set-root:root-if-exist
#   recommended_action: "Change the proxy kubeconfig file <path><filename> ownership to root:root if exist"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0072

import data.lib.kubernetes

types := ["master", "worker"]

validate_kube_config_file_ownership(sp) := {"kubeconfigFileExistsOwnership": violation} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeconfigFileExistsOwnership) > 0
	violation := {ownership | ownership = sp.info.kubeconfigFileExistsOwnership.values[_]; ownership != "root:root"}
	count(violation) > 0
}

deny[res] {
	output := validate_kube_config_file_ownership(input)
	msg := "Ensure proxy kubeconfig file ownership is set to root:root if exists"
	res := result.new(msg, output)
}
