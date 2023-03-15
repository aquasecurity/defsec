# METADATA
# title: "Ensure that the --anonymous-auth argument is set to false"
# description: "Disable anonymous requests to the Kubelet server."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0079
#   avd_id: AVD-KCV-0079
#   severity: CRITICAL
#   short_code: disable-anonymous-requests-kubelet-server.
#   recommended_action: "Disable anonymous requests to the Kubelet server"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0079

import data.lib.kubernetes

types := ["master", "worker"]

validate_kubelet_anonymous_auth_set(sp) := {"kubeletAnonymousAuthArgumentSet": violation} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {anonymous_auth | anonymous_auth = sp.info.kubeletAnonymousAuthArgumentSet.values[_]; anonymous_auth == "true"}
	count(violation) > 0
}

validate_kubelet_anonymous_auth_set(sp) := {"kubeletAnonymousAuthArgumentSet": anonymous_auth} {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletAnonymousAuthArgumentSet.values) == 0
	anonymous_auth = {}
}

deny[res] {
	output := validate_kubelet_anonymous_auth_set(input)
	msg := "Ensure that the --anonymous-auth argument is set to false"
	res := result.new(msg, output)
}
