# METADATA
# title: "Ensure that the API server pod specification file permissions are set to 600 or more restrictive"
# description: "Ensure that the API server pod specification file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0048
#   avd_id: AVD-KCV-0048
#   severity: HIGH
#   short_code: ensure-api-server-pod-specification-file-permissions-set-600-or-more-restrictive
#   recommended_action: "Change the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml permissions of 600 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0048

import data.lib.kubernetes

validate_spec_permission(sp) := {"kubeAPIServerSpecFilePermission": violation} {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {permission | permission = sp.info.kubeAPIServerSpecFilePermission.values[_]; permission > 600}
	count(violation) > 0
}

deny[res] {
	output := validate_spec_permission(input)
	msg := "Ensure that the API server pod specification file permissions is set to 600 or more restrictive"
	res := result.new(msg, output)
}
