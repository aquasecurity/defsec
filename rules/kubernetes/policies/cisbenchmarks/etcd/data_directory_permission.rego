# METADATA
# title: "Ensure that the etcd data directory permissions are set to 700 or more restrictive"
# description: "Ensure that the etcd data directory has permissions of 700 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0058
#   avd_id: AVD-KCV-0058
#   severity: LOW
#   short_code: ensure-etcd-data-directory-permissions-set-700-or-more-restrictive
#   recommended_action: "Change the etcd data directory /var/lib/etcd permissions of 700 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0058

import data.lib.kubernetes

validate_spec_permission(sp) := {"etcdDataDirectoryPermissions": permission} {
	sp.kind == "NodeInfo"
	sp.type == "master"
	permission := sp.info.etcdDataDirectoryPermissions.values[_]
	permission > 700
}

deny[res] {
	output := validate_spec_permission(input)
	msg := "Ensure that the etcd data directory permissions are set to 700 or more restrictive"
	res := result.new(msg, output)
}
