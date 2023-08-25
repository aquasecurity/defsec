# METADATA
# title: "SYS_MODULE capability added"
# description: "The SYS_MODULE capability grants attackers the ability to install and remove kernel modules, posing serious security risks."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
# custom:
#   id: KSV120
#   avd_id: AVD-KSV-0120
#   severity: HIGH
#   short_code: no-sysmodule-capability
#   recommended_action: "To mitigate potential security risks, it is strongly recommended to remove the SYS_MODULE capability from 'containers[].securityContext.capabilities.add'. It is advisable to follow the practice of dropping all capabilities and only adding the necessary ones."
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
package builtin.kubernetes.KSV120

import data.lib.kubernetes

default failCapsSysModule = false

# getCapsSysAdmin returns the names of all containers which include
# 'SYS_ADMIN' in securityContext.capabilities.add.
getCapsSysModule[container] {
	container := kubernetes.containers[_]
	container.securityContext.capabilities.add[_] == "SYS_MODULE"
}

deny[res] {
	output := getCapsSysModule[_]
	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should not include 'SYS_MODULE' in securityContext.capabilities.add", [getCapsSysModule[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, output)
}
