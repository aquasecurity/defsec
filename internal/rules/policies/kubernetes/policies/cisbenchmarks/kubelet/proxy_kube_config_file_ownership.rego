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

validate_service_file_ownership(sp) := {"kubeconfigFileExistsOwnership": ownership} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeconfigFileExistsOwnership) > 0
	ownership := sp.info.kubeconfigFileExistsOwnership[_]
	not ownership == "root:root"
}

deny[res] {
	output := validate_service_file_ownership(input)
	msg := "Ensure that the kubelet service file ownership is set to root:root"
	res := result.new(msg, output)
}
