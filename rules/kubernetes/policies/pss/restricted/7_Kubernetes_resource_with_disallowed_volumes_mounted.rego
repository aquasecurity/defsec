# METADATA
# title: "Kubernetes resource with disallowed volumes mounted"
# description: "HostPath present many security risks and as a security practice it is better to avoid critical host paths mounts."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV121
#   avd_id: AVD-KSV-0121
#   severity: HIGH
#   short_code: no-k8s-with-disallowed-volumes
#   recommended_action: "Do not Set 'spec.volumes[*].hostPath.path' to any of the disallowed volumes."
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
package builtin.kubernetes.KSV121

import data.lib.kubernetes
import data.lib.utils

# Add disallowed volume type
disallowedVolumes = [
	"/",
	"/boot",
	"/dev",
	"/etc",
	"/lib",
	"/proc",
	"/sys",
	"/usr",
	"/var/lib/docker",
]

# getDisallowedVolumes returns a list of volumes
# which are set to any of the disallowed hostPath volumes
getDisallowedVolumes[path] {
	hostpath := kubernetes.volumes[_].hostPath.path
	volume := disallowedVolumes[_]
	volume == hostpath
	path := hostpath
}

# failVolumes is true if any of volume has a disallowed volumes
failVolumes {
	count(getDisallowedVolumes) > 0
}

deny[res] {
	failVolumes
	msg := kubernetes.format(sprintf("%s %s in %s namespace shouldn't have volumes set to %s", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace, getDisallowedVolumes]))
	res := result.new(msg, input.spec)
}
