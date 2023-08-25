# METADATA
# title: Access to host IPC namespace
# description: Sharing the host’s IPC namespace allows container processes to communicate with processes on the host.
# scope: package
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: KSV008
#   avd_id: AVD-KSV-0008
#   severity: HIGH
#   short_code: no-shared-ipc-namespace
#   recommended_action: Do not set 'spec.template.spec.hostIPC' to true.
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
package builtin.kubernetes.KSV008

import data.lib.kubernetes

default failHostIPC = false

# failHostIPC is true if spec.hostIPC is set to true (on all resources)
failHostIPC {
	kubernetes.host_ipcs[_] == true
}

deny[res] {
	failHostIPC
	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.spec.hostIPC' to true", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
