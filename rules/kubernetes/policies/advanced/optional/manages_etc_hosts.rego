# METADATA
# title: "Manages /etc/hosts"
# description: "Managing /etc/hosts aliases can prevent the container engine from modifying the file after a pod’s containers have already been started."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: KSV007
#   avd_id: AVD-KSV-0007
#   severity: LOW
#   short_code: no-hostaliases
#   recommended_action: "Do not set 'spec.template.spec.hostAliases'."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: pod
#         - kind: replicaset
#         - kind: replicationcontroller
#         - kind: deployment
#         - kind: statefulset
#         - kind: daemonset
#         - kind: cronjob
#         - kind: job
package builtin.kubernetes.KSV007

import data.lib.kubernetes
import data.lib.utils

# failHostAliases is true if spec.hostAliases is set (on all controllers)
failHostAliases[spec] {
	spec := kubernetes.host_aliases[_]
	utils.has_key(spec, "hostAliases")
}

deny[res] {
	spec := failHostAliases[_]
	msg := kubernetes.format(sprintf("'%s' '%s' in '%s' namespace should not set spec.template.spec.hostAliases", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, spec)
}
