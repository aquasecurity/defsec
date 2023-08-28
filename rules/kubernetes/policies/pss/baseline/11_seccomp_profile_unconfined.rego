# METADATA
# title: "Seccomp policies disabled"
# description: "A program inside the container can bypass Seccomp protection policies."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV104
#   avd_id: AVD-KSV-0104
#   severity: MEDIUM
#   short_code: no-seccomp-unconfined
#   recommended_action: "Specify seccomp either by annotation or by seccomp profile type having allowed values as per pod security standards"
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
package builtin.kubernetes.KSV104

import data.lib.kubernetes
import data.lib.utils

# getSeccompContainers returns all containers which have a seccomp
# profile set and is profile not set to "unconfined"
getSeccompContainers[container] {
	some i
	keys := [key | key := sprintf("%s/%s", [
		"container.seccomp.security.alpha.kubernetes.io",
		kubernetes.containers[_].name,
	])]
	seccomp := object.filter(kubernetes.annotations[_], keys)
	val := seccomp[i]
	val != "unconfined"
	[a, c] := split(i, "/")
	container = c
}

# getNoSeccompContainers returns all containers which do not have
# a seccomp profile specified or profile set to "unconfined"
getNoSeccompContainers[container] {
	container := kubernetes.containers[_].name
	not getSeccompContainers[container]
}

# getContainersWithDisallowedSeccompProfileType returns all containers which have a seccomp
# profile set and is profile set to "Unconfined"
getContainersWithDisallowedSeccompProfileType[name] {
	container := kubernetes.containers[_]
	type := container.securityContext.seccompProfile.type
	type == "Unconfined"
	name = container.name
}

# getContainersWithDisallowedSeccompProfileType returns all containers which do not have
# a seccomp profile type specified
getContainersWithDisallowedSeccompProfileType[name] {
	container := kubernetes.containers[_]
	not container.securityContext.seccompProfile.type
	name = container.name
}

deny[res] {
	cause := getContainersWithDisallowedSeccompProfileType[_]
	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should specify a seccomp profile", [getNoSeccompContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, cause)
}
