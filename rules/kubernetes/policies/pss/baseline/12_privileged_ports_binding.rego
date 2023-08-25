# METADATA
# title: "Prevent binding to privileged ports"
# description: "The ports which are lower than 1024 receive and transmit various sensitive and privileged data. Allowing containers to use them can bring serious implications."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/
# custom:
#   id: KSV117
#   avd_id: AVD-KSV-0117
#   severity: HIGH
#   short_code: no-privilege-port-binding
#   recommended_action: "Do not map the container ports to privileged host ports when starting a container."
#   input:
#     selector:
#     - type: kubernetes
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
package builtin.kubernetes.KSV117

import data.lib.kubernetes

default failPrivilegedPort = false

# failPrivilegedPort is true if spec.containers.ports.containerPort is set to less than 1024
failPrivilegedPort {
	containerPort := kubernetes.containers[_].ports[_].containerPort
	containerPort < 1024
}

deny[res] {
	failPrivilegedPort
	msg := kubernetes.format(sprintf("%s %s in %s namespace should not set spec.template.spec.containers.ports.containerPort to less than 1024", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, failPrivilegedPort)
}
