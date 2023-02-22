# METADATA
# title: "Ensure that the etcd pod specification file ownership is set to root:root"
# description: "Ensure that the etcd pod specification file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0055
#   avd_id: AVD-KCV-0055
#   severity: HIGH
#   short_code: ensure-etcd-pod-specification-ownership-set-root:root.
#   recommended_action: "Change the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0055

import data.lib.kubernetes

validate_spec_ownership(sp) := {"kubeEtcdSpecFileOwnership": violation} {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {ownership | ownership = sp.info.kubeEtcdSpecFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny[res] {
	output := validate_spec_ownership(input)
	msg := "Ensure that the etcd pod specification file ownership is set to root:root"
	res := result.new(msg, output)
}
