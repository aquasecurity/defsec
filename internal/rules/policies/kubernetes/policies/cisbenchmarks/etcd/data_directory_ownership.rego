# METADATA
# title: "Ensure that the etcd data directory ownership is set to etcd:etcd"
# description: "Ensure that the etcd data directory ownership is set to etcd:etcd."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0059
#   avd_id: AVD-KCV-0059
#   severity: HIGH
#   short_code: ensure-etcd-data-directory-ownership-set-etcd:etcd.
#   recommended_action: "Change the etcd data directory /var/lib/etcd ownership to etcd:etcd"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0059

import data.lib.kubernetes

validate_spec_ownership(sp) := {"EtcdDataDirectoryOwnership": ownership} {
	sp.kind == "Nodeinfo"
	sp.type == "master"
	ownership := sp.info.EtcdDataDirectoryOwnership[_]
	not ownership == "etcd:etcd"
}

deny[res] {
	output := validate_spec_ownership(input)
	msg := "Ensure that the etcd data directory ownership is set to etcd:etcd"
	res := result.new(msg, output)
}
